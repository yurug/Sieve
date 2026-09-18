// VPA-X01 fork: red tests for replay-by-approval-id on the REST ops handler
// (executeOperation). Before this feature, an approval item approved after
// the requester's 5-minute WaitForResolution timed out could never be
// executed — the agent had no way to redeem it. The X-Sieve-Approval-Id
// header lets a caller that already knows an approved item's id execute it
// directly, using the item's stored request_data (never the request body),
// exactly once.
package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// replayTestSetup wires a router + mock connection + role + token and
// returns everything a replay test needs, including a helper to submit an
// approval item scoped to that token/connection/operation.
func replayTestSetup(t *testing.T) (srv *httptest.Server, env *testenv.Env, tok *tokens.CreateResult, connID string) {
	t.Helper()
	env = testenv.New(t)
	connID = "mock-conn"
	role := env.SetupConnectionAndRole(t, connID)
	result, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleIDs: []string{role.ID}})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv = httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)
	return srv, env, result, connID
}

// submitApprovedItem creates and approves an approval item, returning it.
func submitApprovedItem(t *testing.T, env *testenv.Env, tokenID, connID, operation string, requestData map[string]any) *approval.Item {
	t.Helper()
	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID:      tokenID,
		ConnectionID: connID,
		Operation:    operation,
		RequestData:  requestData,
	})
	if err != nil {
		t.Fatalf("submit approval: %v", err)
	}
	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatalf("get approved item: %v", err)
	}
	return got
}

func replayRequest(t *testing.T, srv *httptest.Server, token, connID, operation, approvalID, body string) *http.Response {
	t.Helper()
	var r *http.Request
	var err error
	if body != "" {
		r, err = http.NewRequest(http.MethodPost, srv.URL+"/api/v1/connections/"+connID+"/ops/"+operation, strings.NewReader(body))
	} else {
		r, err = http.NewRequest(http.MethodPost, srv.URL+"/api/v1/connections/"+connID+"/ops/"+operation, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	if approvalID != "" {
		r.Header.Set("X-Sieve-Approval-Id", approvalID)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// P: replaying an approved item executes the connector op using the ITEM's
// stored request_data, ignoring whatever the replay request's body carries.
// A second replay of the same id gets 409 (already executed) and the
// connector is invoked exactly once.
func TestApprovalReplay_ExecutesOnce_SecondCallConflict(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)

	approved := map[string]any{"to": []any{"approved@example.com"}, "subject": "s", "body": "b"}
	item := submitApprovedItem(t, env, tok.Token.ID, connID, "send_email", approved)

	// The replay body carries DIFFERENT params — must be ignored.
	resp := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", item.ID,
		`{"to":["ignored@example.com"],"subject":"ignored","body":"ignored"}`)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first replay: want 200, got %d (%s)", resp.StatusCode, body)
	}

	if n := len(env.Mock.Calls); n != 1 {
		t.Fatalf("expected exactly 1 connector call, got %d", n)
	}
	call := env.Mock.Calls[0]
	if call.Operation != "send_email" {
		t.Errorf("call operation = %q, want send_email", call.Operation)
	}
	to, _ := call.Params["to"].([]any)
	if len(to) != 1 || to[0] != "approved@example.com" {
		t.Errorf("connector executed with %v, want the approved item's request_data, not the replay body", call.Params)
	}

	// Second replay of the same id must not execute again.
	resp2 := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", item.ID, "")
	body2 := readBody(t, resp2)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second replay: want 409, got %d (%s)", resp2.StatusCode, body2)
	}
	if len(env.Mock.Calls) != 1 {
		t.Fatalf("second replay must not execute the connector again, got %d calls", len(env.Mock.Calls))
	}

	got, err := env.Approval.Get(item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExecutedAt == nil {
		t.Error("expected executed_at to be set after replay")
	}
}

// P: an unknown approval id is a mismatch (403), not a 404/500 — avoids
// distinguishing "id doesn't exist" from "id belongs to someone else".
func TestApprovalReplay_UnknownID_Mismatch(t *testing.T) {
	srv, _, tok, connID := replayTestSetup(t)

	resp := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", "does-not-exist", "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d (%s)", resp.StatusCode, body)
	}
	if !jsonContains(body, "approval mismatch") {
		t.Errorf("body = %s, want approval mismatch", body)
	}
}

// P: an approval item belonging to a DIFFERENT token cannot be replayed by
// this token, even against the same connection/operation.
func TestApprovalReplay_TokenMismatch(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)

	item := submitApprovedItem(t, env, "some-other-token-id", connID, "send_email",
		map[string]any{"to": []any{"x@example.com"}, "subject": "s", "body": "b"})

	resp := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", item.ID, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d (%s)", resp.StatusCode, body)
	}
	if !jsonContains(body, "approval mismatch") {
		t.Errorf("body = %s, want approval mismatch", body)
	}
	if len(env.Mock.Calls) != 0 {
		t.Error("mismatched replay must not execute the connector")
	}
}

// P: an approval item submitted for a DIFFERENT operation cannot be
// replayed against this operation's URL.
func TestApprovalReplay_OperationMismatch(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)

	item := submitApprovedItem(t, env, tok.Token.ID, connID, "archive",
		map[string]any{"message_id": "m1"})

	resp := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", item.ID, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d (%s)", resp.StatusCode, body)
	}
	if !jsonContains(body, "approval mismatch") {
		t.Errorf("body = %s, want approval mismatch", body)
	}
}

// P: a still-pending item is 409 ("approval pending"), distinct from the
// 409 used for "already executed".
func TestApprovalReplay_Pending409(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)

	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: tok.Token.ID, ConnectionID: connID, Operation: "send_email",
		RequestData: map[string]any{"to": []any{"x@example.com"}, "subject": "s", "body": "b"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", item.ID, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409, got %d (%s)", resp.StatusCode, body)
	}
	if !jsonContains(body, "approval pending") {
		t.Errorf("body = %s, want approval pending", body)
	}
}

// P: a rejected (or TTL-expired, which is stored as rejected/resolved_by=
// expired) item is 403 ("approval rejected").
func TestApprovalReplay_Rejected403(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)

	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: tok.Token.ID, ConnectionID: connID, Operation: "send_email",
		RequestData: map[string]any{"to": []any{"x@example.com"}, "subject": "s", "body": "b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Approval.Reject(item.ID); err != nil {
		t.Fatal(err)
	}

	resp := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", item.ID, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d (%s)", resp.StatusCode, body)
	}
	if !jsonContains(body, "approval rejected") {
		t.Errorf("body = %s, want approval rejected", body)
	}
}

// P: the normal (no X-Sieve-Approval-Id header) path is unchanged — a
// fresh approval_required request without the header still blocks
// synchronously (existing behavior), it doesn't take the replay branch.
func TestApprovalReplay_HeaderAbsent_NormalPathUnaffected(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)

	// Require approval for this connection.
	cedar := `@approval("required")
permit(principal, action, resource in Sieve::Connection::"` + connID + `");`
	if _, err := env.IAM.CreatePolicy("require-approval", "", cedar, true); err != nil {
		t.Fatal(err)
	}

	done := make(chan *http.Response, 1)
	go func() {
		done <- replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", "",
			`{"to":["x@example.com"],"subject":"s","body":"b"}`)
	}()

	// Approve whatever shows up. The submitting request runs in its own
	// goroutine above, so poll with a bounded sleep rather than a tight
	// spin — a spin loop with no delay can run its full iteration budget
	// before the other goroutine's request even reaches Submit.
	var pendingID string
	for i := 0; i < 200; i++ {
		pending, _ := env.Approval.ListPending()
		if len(pending) > 0 {
			pendingID = pending[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pendingID == "" {
		t.Fatal("expected a pending approval item to appear")
	}
	if err := env.Approval.Approve(pendingID); err != nil {
		t.Fatal(err)
	}

	resp := <-done
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 after approval, got %d (%s)", resp.StatusCode, body)
	}
}

func jsonContains(body, substr string) bool {
	return strings.Contains(body, substr)
}
