// VPA-X01 fork: red tests for the admin JSON approvals API
// (GET/POST /api/approvals...). The existing /approvals HTML page has no
// machine-readable equivalent, which is what an external approval
// dashboard/bot needs. Written before server.go registers the routes, so
// this file starts red.
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/approval"
	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func newApprovalsAPITestServer(t *testing.T) (*httptest.Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	scriptgenSvc := scriptgen.NewService(env.Connections, env.Settings)
	srv := NewServer(
		env.Tokens, env.Connections, env.Roles,
		env.Registry, env.Approval, env.Audit,
		"", env.Settings, scriptgenSvc,
		env.Keyring, env.DB, "127.0.0.1:0",
	)
	srv.SetAuth(env.Operator, env.Session)
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, env
}

type approvalsListResponse struct {
	Items []approval.Item `json:"items"`
}

type approvalItemResponse struct {
	OK   bool          `json:"ok"`
	Item approval.Item `json:"item"`
}

// P: GET /api/approvals defaults to pending items; status=all returns
// resolved items too; limit bounds the count.
func TestAPIApprovalsList(t *testing.T) {
	ts, env := newApprovalsAPITestServer(t)

	for i := 0; i < 3; i++ {
		if _, err := env.Approval.Submit(&approval.SubmitRequest{
			TokenID: "t", ConnectionID: "c", Operation: "op", RequestData: map[string]any{"n": i},
		}); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: "t", ConnectionID: "c", Operation: "op", RequestData: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Approval.Approve(resolved.ID); err != nil {
		t.Fatal(err)
	}

	resp, err := env.AdminClient().Get(ts.URL + "/api/approvals")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("default status=pending: want 200, got %d", resp.StatusCode)
	}
	var list approvalsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 3 {
		t.Fatalf("default (pending) items = %d, want 3", len(list.Items))
	}
	for _, it := range list.Items {
		if it.RequestData == nil {
			t.Error("request_data should decode as an object, got nil")
		}
	}

	respAll, err := env.AdminClient().Get(ts.URL + "/api/approvals?status=all&limit=2")
	if err != nil {
		t.Fatal(err)
	}
	defer respAll.Body.Close()
	var listAll approvalsListResponse
	if err := json.NewDecoder(respAll.Body).Decode(&listAll); err != nil {
		t.Fatal(err)
	}
	if len(listAll.Items) != 2 {
		t.Fatalf("status=all&limit=2 items = %d, want 2", len(listAll.Items))
	}
}

// P: POST /api/approvals/{id}/approve marks the item approved and returns
// the updated item as JSON.
func TestAPIApprovalApprove_Basic(t *testing.T) {
	ts, env := newApprovalsAPITestServer(t)

	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: "t", ConnectionID: "c", Operation: "send_email",
		RequestData: map[string]any{"to": "a@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := env.AdminClient().Post(ts.URL+"/api/approvals/"+item.ID+"/approve", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var out approvalItemResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.OK {
		t.Error("ok should be true")
	}
	if out.Item.Status != approval.StatusApproved {
		t.Errorf("status = %s, want approved", out.Item.Status)
	}
	if out.Item.RequestData["to"] != "a@example.com" {
		t.Errorf("request_data unexpectedly changed: %v", out.Item.RequestData)
	}
}

// P: edit-then-approve replaces request_data BEFORE marking approved, and
// the replaced value is what gets returned/persisted.
func TestAPIApprovalApprove_EditThenApprove(t *testing.T) {
	ts, env := newApprovalsAPITestServer(t)

	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: "t", ConnectionID: "c", Operation: "send_email",
		RequestData: map[string]any{"to": "wrong@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	body := `{"request_data":{"to":"corrected@example.com"}}`
	resp, err := env.AdminClient().Post(ts.URL+"/api/approvals/"+item.ID+"/approve", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var out approvalItemResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Item.RequestData["to"] != "corrected@example.com" {
		t.Errorf("request_data.to = %v, want corrected@example.com", out.Item.RequestData["to"])
	}
	if out.Item.Status != approval.StatusApproved {
		t.Errorf("status = %s, want approved", out.Item.Status)
	}

	// The edit must be audited distinctly from the approve action.
	rows, err := env.Audit.List(&audit.ListFilter{Operation: "approval.edit"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("approval.edit audit rows = %d, want 1", len(rows))
	}
}

// P: unknown id is 404 JSON; an already-resolved item is 409 JSON.
func TestAPIApprovalApprove_UnknownAndAlreadyResolved(t *testing.T) {
	ts, env := newApprovalsAPITestServer(t)

	resp, err := env.AdminClient().Post(ts.URL+"/api/approvals/does-not-exist/approve", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: want 404, got %d", resp.StatusCode)
	}

	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: "t", ConnectionID: "c", Operation: "op", RequestData: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Approval.Approve(item.ID); err != nil {
		t.Fatal(err)
	}
	resp2, err := env.AdminClient().Post(ts.URL+"/api/approvals/"+item.ID+"/approve", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("already-resolved: want 409, got %d", resp2.StatusCode)
	}
}

// P: POST /api/approvals/{id}/reject marks the item rejected and returns it.
func TestAPIApprovalReject_Basic(t *testing.T) {
	ts, env := newApprovalsAPITestServer(t)

	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: "t", ConnectionID: "c", Operation: "op", RequestData: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := env.AdminClient().Post(ts.URL+"/api/approvals/"+item.ID+"/reject", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var out approvalItemResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Item.Status != approval.StatusRejected {
		t.Errorf("status = %s, want rejected", out.Item.Status)
	}
}

// P: the JSON API is gated by the same operator-session + CSRF rule as
// every other admin POST — a session cookie without a CSRF token is
// refused.
func TestAPIApprovalApprove_RequiresCSRF(t *testing.T) {
	ts, env := newApprovalsAPITestServer(t)

	item, err := env.Approval.Submit(&approval.SubmitRequest{
		TokenID: "t", ConnectionID: "c", Operation: "op", RequestData: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/approvals/"+item.ID+"/approve", nil)
	req.AddCookie(env.SessionCookie())
	// Deliberately no X-CSRF-Token header.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 without CSRF token, got %d", resp.StatusCode)
	}
}
