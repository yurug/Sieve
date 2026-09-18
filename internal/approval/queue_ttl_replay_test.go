// VPA-X01 fork: red tests for the approval TTL / expiry, edit-then-approve
// request_data mutation, execute-exactly-once marker, and best-effort
// webhook notification added to the approval queue. Written before queue.go
// gained SetTTL/ExpireStale/SetRequestData/MarkExecuted/SetWebhookURL, so
// this file starts red (does not compile) until those land.
package approval_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// backdateCreatedAt directly rewrites an item's created_at column so tests
// can simulate age without sleeping. Approval tests elsewhere in this
// package already reach into env.DB for setup-only SQL, so this mirrors
// that pattern rather than adding a test-only Queue method that production
// code would never call.
func backdateCreatedAt(t *testing.T, env *testenv.Env, id string, age time.Duration) {
	t.Helper()
	when := time.Now().UTC().Add(-age)
	if _, err := env.DB.Exec(`UPDATE approval_queue SET created_at = ? WHERE id = ?`, when, id); err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}
}

// P: ExpireStale marks only stale PENDING items — resolved items and
// fresh pending items are untouched.
func TestExpireStale_MarksOnlyStalePending(t *testing.T) {
	env := testenv.New(t)
	env.Approval.SetTTL(1 * time.Minute)

	stale := submitTestItem(t, env.Approval, "op_stale")
	backdateCreatedAt(t, env, stale.ID, 2*time.Minute)

	fresh := submitTestItem(t, env.Approval, "op_fresh")

	alreadyResolved := submitTestItem(t, env.Approval, "op_resolved")
	backdateCreatedAt(t, env, alreadyResolved.ID, 2*time.Minute)
	if err := env.Approval.Approve(alreadyResolved.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	n, err := env.Approval.ExpireStale()
	if err != nil {
		t.Fatalf("expire stale: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 item expired, got %d", n)
	}

	got, err := env.Approval.Get(stale.ID)
	if err != nil {
		t.Fatalf("get stale: %v", err)
	}
	if got.Status != approval.StatusRejected {
		t.Errorf("stale item status = %s, want rejected", got.Status)
	}
	if got.ResolvedBy != "expired" {
		t.Errorf("stale item resolved_by = %q, want %q", got.ResolvedBy, "expired")
	}
	if got.ResolvedAt == nil {
		t.Error("stale item resolved_at should be set")
	}

	gotFresh, err := env.Approval.Get(fresh.ID)
	if err != nil {
		t.Fatalf("get fresh: %v", err)
	}
	if gotFresh.Status != approval.StatusPending {
		t.Errorf("fresh item status = %s, want pending (not yet stale)", gotFresh.Status)
	}

	gotResolved, err := env.Approval.Get(alreadyResolved.ID)
	if err != nil {
		t.Fatalf("get already-resolved: %v", err)
	}
	if gotResolved.ResolvedBy == "expired" {
		t.Error("already-approved item must not be re-marked as expired")
	}
}

// P: ExpireStale is a no-op when the queue's TTL is unset (0, the default) —
// callers can invoke it unconditionally from a ticking goroutine without
// checking whether a TTL was configured.
func TestExpireStale_NoopWhenTTLUnset(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "op")
	backdateCreatedAt(t, env, item.ID, 24*time.Hour)

	n, err := env.Approval.ExpireStale()
	if err != nil {
		t.Fatalf("expire stale: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 expired with TTL unset, got %d", n)
	}

	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != approval.StatusPending {
		t.Errorf("status = %s, want pending", got.Status)
	}
}

// P: Submit stamps expires_at = created_at + ttl when a TTL is configured,
// and leaves it nil when the TTL is 0.
func TestSubmit_SetsExpiresAtFromTTL(t *testing.T) {
	env := testenv.New(t)
	env.Approval.SetTTL(30 * time.Minute)

	item := submitTestItem(t, env.Approval, "op")
	if item.ExpiresAt == nil {
		t.Fatal("expected expires_at to be set when TTL is configured")
	}
	wantExpiry := item.CreatedAt.Add(30 * time.Minute)
	if diff := item.ExpiresAt.Sub(wantExpiry); diff < -time.Second || diff > time.Second {
		t.Errorf("expires_at = %v, want ~%v", item.ExpiresAt, wantExpiry)
	}

	env.Approval.SetTTL(0)
	item2 := submitTestItem(t, env.Approval, "op2")
	if item2.ExpiresAt != nil {
		t.Errorf("expected nil expires_at with TTL disabled, got %v", item2.ExpiresAt)
	}
}

// P: SetRequestData (edit-then-approve) overwrites a PENDING item's stored
// request_data; it refuses to touch an already-resolved item so an edit can
// never race a resolution.
func TestSetRequestData_PendingOnly(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "op")
	edited := map[string]any{"to": "corrected@example.com"}
	if err := env.Approval.SetRequestData(item.ID, edited); err != nil {
		t.Fatalf("set request data on pending item: %v", err)
	}
	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RequestData["to"] != "corrected@example.com" {
		t.Errorf("request_data.to = %v, want corrected@example.com", got.RequestData["to"])
	}

	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := env.Approval.SetRequestData(item.ID, map[string]any{"to": "too-late@example.com"}); err == nil {
		t.Fatal("expected error editing an already-resolved item")
	}
}

// P: MarkExecuted redeems an approved item's replay token exactly once —
// concurrent/duplicate replay calls after the first must not re-execute.
func TestMarkExecuted_ExactlyOnce(t *testing.T) {
	env := testenv.New(t)

	item := submitTestItem(t, env.Approval, "op")
	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	first, err := env.Approval.MarkExecuted(item.ID)
	if err != nil {
		t.Fatalf("first MarkExecuted: %v", err)
	}
	if !first {
		t.Fatal("first MarkExecuted should succeed (executed_at was NULL)")
	}

	second, err := env.Approval.MarkExecuted(item.ID)
	if err != nil {
		t.Fatalf("second MarkExecuted: %v", err)
	}
	if second {
		t.Fatal("second MarkExecuted should fail — item already executed")
	}

	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ExecutedAt == nil {
		t.Error("expected executed_at to be set")
	}
}

// P: SetWebhookURL configures a best-effort POST on Submit that carries
// item identity but never the request_data payload (the webhook receiver is
// outside Sieve's credential boundary).
func TestSubmit_NotifiesWebhookWithoutRequestData(t *testing.T) {
	env := testenv.New(t)

	received := make(chan map[string]any, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	env.Approval.SetWebhookURL(ts.URL)
	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID:      "tok-1",
		ConnectionID: "conn-1",
		Operation:    "send_email",
		RequestData:  map[string]any{"to": "secret-recipient@example.com"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case body := <-received:
		if body["id"] != item.ID {
			t.Errorf("webhook id = %v, want %v", body["id"], item.ID)
		}
		if body["operation"] != "send_email" {
			t.Errorf("webhook operation = %v, want send_email", body["operation"])
		}
		if _, ok := body["request_data"]; ok {
			t.Error("webhook payload must not include request_data")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook POST")
	}
}

// P: an unconfigured webhook (the default) means Submit never makes an
// outbound call — no URL, nothing to do.
func TestSubmit_NoWebhookByDefault(t *testing.T) {
	env := testenv.New(t)
	// No SetWebhookURL call. Submit must not panic or block on a nil/empty URL.
	if _, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: "t", ConnectionID: "c", Operation: "op", RequestData: map[string]any{},
	}); err != nil {
		t.Fatalf("submit without webhook configured: %v", err)
	}
}
