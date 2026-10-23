package web

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/googlerevoke"
)

const revokeTestRefresh = "1//refresh-SECRET-for-revoke-test"

// revokeStub stands in for Google's revocation endpoint and records the
// tokens it received.
func revokeStub(t *testing.T, status int, body string) (*googlerevoke.Revoker, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(raw))
		seen = append(seen, v.Get("token"))
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &googlerevoke.Revoker{Endpoint: srv.URL, Client: srv.Client()}, &seen
}

func addGoogleConnection(t *testing.T, s *Server, id string) {
	t.Helper()
	cfg := map[string]any{
		"email":       id + "@example.com",
		"client_id":   "test.apps.googleusercontent.com",
		"oauth_token": map[string]any{"access_token": "access-x", "refresh_token": revokeTestRefresh},
	}
	if err := s.connections.Add(id, "google", id, cfg); err != nil {
		t.Fatal(err)
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func TestConnectionDeleteRevokesGoogleGrantFirst(t *testing.T) {
	s, env := profileTestServer(t)
	revoker, seen := revokeStub(t, 200, `{}`)
	s.SetGoogleRevoker(revoker)
	addGoogleConnection(t, s, "mailbox")

	rec := profilePost(t, s, env, "/connections/mailbox/delete", url.Values{})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/connections" {
		t.Fatalf("delete: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := rec.Header().Get(googleRevokeHeader); got != "revoked" {
		t.Errorf("outcome header %q", got)
	}
	if len(*seen) != 1 || (*seen)[0] != revokeTestRefresh {
		t.Errorf("revocation endpoint did not get the refresh token exactly once (%d calls)", len(*seen))
	}
	if ok, _ := env.Connections.Exists("mailbox"); ok {
		t.Error("connection row survived")
	}
}

func TestConnectionDeleteFailedRevokeStillDeletesAndLeaksNothing(t *testing.T) {
	s, env := profileTestServer(t)
	revoker, seen := revokeStub(t, 503, "unavailable")
	s.SetGoogleRevoker(revoker)
	addGoogleConnection(t, s, "mailbox")
	logs := captureLog(t)

	rec := profilePost(t, s, env, "/connections/mailbox/delete", url.Values{})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/connections" {
		t.Fatalf("delete: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := rec.Header().Get(googleRevokeHeader); got != "failed" {
		t.Errorf("outcome header %q", got)
	}
	if len(*seen) != 1 {
		t.Errorf("want exactly one attempt (no retry), got %d", len(*seen))
	}
	if ok, _ := env.Connections.Exists("mailbox"); ok {
		t.Error("a failed revoke must still delete the stored token")
	}
	if !strings.Contains(logs.String(), "status 503") {
		t.Errorf("typed failure not logged: %q", logs.String())
	}
	entries, err := env.Audit.List(&audit.ListFilter{ConnectionID: "mailbox"})
	if err != nil {
		t.Fatal(err)
	}
	var revokeRow *audit.Entry
	for i := range entries {
		if strings.Contains(entries[i].Params, "SECRET") || strings.Contains(entries[i].ResponseSummary, "SECRET") {
			t.Errorf("audit row %s carries the token", entries[i].Operation)
		}
		if entries[i].Operation == "connection.google_revoke" {
			revokeRow = &entries[i]
		}
	}
	if revokeRow == nil || !strings.Contains(revokeRow.Params, `"failure_kind":"status"`) || revokeRow.PolicyResult != "error" {
		t.Errorf("typed failure not audited: %+v", revokeRow)
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Error("log carries the token")
	}
}

func TestConnectionDeleteAlreadyInvalidCountsAsWithdrawn(t *testing.T) {
	s, env := profileTestServer(t)
	revoker, _ := revokeStub(t, 400, `{"error":"invalid_token"}`)
	s.SetGoogleRevoker(revoker)
	addGoogleConnection(t, s, "mailbox")
	rec := profilePost(t, s, env, "/connections/mailbox/delete", url.Values{})
	if got := rec.Header().Get(googleRevokeHeader); got != "already_invalid" {
		t.Errorf("outcome header %q", got)
	}
}

func TestConnectionDeleteNonGoogleMakesNoRevokeCall(t *testing.T) {
	s, env := profileTestServer(t)
	revoker, seen := revokeStub(t, 200, `{}`)
	s.SetGoogleRevoker(revoker)
	if err := s.connections.Add("other", "mock", "other", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	rec0 := profilePost(t, s, env, "/connections/other/delete", url.Values{})
	if rec0.Code != http.StatusSeeOther || rec0.Header().Get(googleRevokeHeader) != "" || len(*seen) != 0 {
		t.Errorf("non-Google delete: %d header=%q calls=%d", rec0.Code, rec0.Header().Get(googleRevokeHeader), len(*seen))
	}
	rec := profilePost(t, s, env, "/connections/missing/delete", url.Values{})
	if rec.Code != http.StatusInternalServerError || len(*seen) != 0 {
		t.Errorf("missing connection: %d, %d calls", rec.Code, len(*seen))
	}
}
