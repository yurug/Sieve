// VPA-X01 fork, item A.6: tests for X-Sieve-Approval-Mode: async on the
// REST ops handler. Without this opt-in, executeOperation blocks in
// WaitForResolution for up to 5 minutes on approval_required and, on
// timeout, never surfaces the approval id — the caller has no way to
// redeem it later even with X-Sieve-Approval-Id replay. Async mode answers
// immediately with the id instead, mirroring the 429 shape gmailExecute
// and the transparent proxy already use for the same situation.
package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/testing/testenv"
)

// requireApprovalOn installs an unconditional @approval("required") policy
// for connID, on top of the "allow all" grant replayTestSetup's
// SetupConnectionAndRole already installed — IAM's obligation semantics OR
// the two together into approval_required (see internal/iam/obligations.go:
// "@approval: logical OR across determining permits"), so the plain allow
// grant doesn't defeat this.
func requireApprovalOn(t *testing.T, env *testenv.Env, connID string) {
	t.Helper()
	cedar := `@approval("required")
permit(principal, action, resource in Sieve::Connection::"` + connID + `");`
	if _, err := env.IAM.CreatePolicy("require-approval-async-test", "", cedar, true); err != nil {
		t.Fatal(err)
	}
}

// P: X-Sieve-Approval-Mode: async on an approval_required decision returns
// 429 + Retry-After immediately, with the approval id in the body, and the
// item is left pending (Submit happened, nothing blocked on it).
func TestAsyncApprovalMode_Returns429WithApprovalID(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)
	requireApprovalOn(t, env, connID)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/connections/"+connID+"/ops/send_email", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok.PlaintextToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sieve-Approval-Mode", "async")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After = %q, want 30", got)
	}

	var body struct {
		Error       string  `json:"error"`
		Message     string  `json:"message"`
		ApprovalID  string  `json:"approval_id"`
		ApprovalURL string  `json:"approval_url"`
		ExpiresAt   *string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "approval_required" {
		t.Errorf("error = %q, want approval_required", body.Error)
	}
	if body.ApprovalID == "" {
		t.Fatal("approval_id must be present")
	}
	if body.ApprovalURL != "/api/v1/approvals/"+body.ApprovalID+"/status" {
		t.Errorf("approval_url = %q, want /api/v1/approvals/%s/status", body.ApprovalURL, body.ApprovalID)
	}
	if body.ExpiresAt != nil {
		t.Errorf("expires_at = %v, want null (no --approval-ttl configured in this test)", *body.ExpiresAt)
	}

	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != body.ApprovalID {
		t.Fatalf("expected exactly the submitted item pending, got %+v", pending)
	}
}

// P: an unrecognized X-Sieve-Approval-Mode value is a 400, not a silent
// fallback to blocking or async.
func TestAsyncApprovalMode_InvalidValueRejected(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)
	requireApprovalOn(t, env, connID)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/connections/"+connID+"/ops/send_email", nil)
	req.Header.Set("Authorization", "Bearer "+tok.PlaintextToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sieve-Approval-Mode", "sync") // not a recognized value
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "invalid X-Sieve-Approval-Mode" {
		t.Errorf("error = %q, want %q", body["error"], "invalid X-Sieve-Approval-Mode")
	}

	pending, err := env.Approval.ListPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("an invalid mode must not submit an approval item, got %d pending", len(pending))
	}
}

// P: with the header absent, behavior is byte-for-byte the pre-A.6
// blocking path — approval_required blocks until a human acts, then
// executes inline.
func TestAsyncApprovalMode_HeaderAbsentStillBlocks(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)
	requireApprovalOn(t, env, connID)

	done := make(chan *http.Response, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/connections/"+connID+"/ops/send_email",
			strings.NewReader(`{"to":["x@example.com"],"subject":"s","body":"b"}`))
		req.Header.Set("Authorization", "Bearer "+tok.PlaintextToken)
		req.Header.Set("Content-Type", "application/json")
		// Deliberately no X-Sieve-Approval-Mode header.
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		done <- resp
	}()

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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 after approval, got %d", resp.StatusCode)
	}
}

// P: an id learned from an async 429 can be redeemed exactly once via
// X-Sieve-Approval-Id after a human approves it.
func TestAsyncApprovalMode_ThenReplayExecutesOnce(t *testing.T) {
	srv, env, tok, connID := replayTestSetup(t)
	requireApprovalOn(t, env, connID)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/connections/"+connID+"/ops/send_email",
		strings.NewReader(`{"to":["approved@example.com"],"subject":"s","body":"b"}`))
	req.Header.Set("Authorization", "Bearer "+tok.PlaintextToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sieve-Approval-Mode", "async")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("setup: want 429, got %d", resp.StatusCode)
	}

	if err := env.Approval.Approve(body.ApprovalID); err != nil {
		t.Fatal(err)
	}

	replayResp := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", body.ApprovalID, "")
	replayBody := readBody(t, replayResp)
	if replayResp.StatusCode != http.StatusOK {
		t.Fatalf("replay: want 200, got %d (%s)", replayResp.StatusCode, replayBody)
	}
	if n := len(env.Mock.Calls); n != 1 {
		t.Fatalf("expected exactly 1 connector call, got %d", n)
	}
	to, _ := env.Mock.Calls[0].Params["to"].([]any)
	if len(to) != 1 || to[0] != "approved@example.com" {
		t.Errorf("connector executed with %v, want the approved item's request_data", env.Mock.Calls[0].Params)
	}

	// A second replay must not execute again.
	replayResp2 := replayRequest(t, srv, tok.PlaintextToken, connID, "send_email", body.ApprovalID, "")
	readBody(t, replayResp2)
	if replayResp2.StatusCode != http.StatusConflict {
		t.Fatalf("second replay: want 409, got %d", replayResp2.StatusCode)
	}
	if len(env.Mock.Calls) != 1 {
		t.Fatalf("second replay must not execute the connector again, got %d calls", len(env.Mock.Calls))
	}
}
