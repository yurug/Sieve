package api_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/api"
	"github.com/trilitech/Sieve/internal/connectors/httpproxy"
	"github.com/trilitech/Sieve/internal/roles"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"github.com/trilitech/Sieve/internal/tokens"
)

// TestProxyBodyCutReachesTheAgentAsAnError (VPA-X01 fork, 2026-10-02): an upstream stream that
// goes silent past the idle limit after its headers must reach the agent as a BROKEN response
// through the real router -- before, io.Copy's error was ignored and the chunked response ended
// cleanly, so a cut model answer looked finished.
func TestProxyBodyCutReachesTheAgentAsAnError(t *testing.T) {
	t.Setenv(httpproxy.EnvIdleTimeout, "300ms")
	env := testenv.New(t)

	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"n\":0}\n\n")
		http.NewResponseController(w).Flush()
		select { // silent until the test ends
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(target.Close)
	t.Cleanup(func() { close(release) })

	env.Registry.Register(httpproxy.Meta, httpproxy.Factory)
	if err := env.Connections.Add("llm", "http_proxy", "LLM", map[string]any{
		"target_url":         target.URL,
		"auth_header":        "Authorization",
		"auth_value":         "sk-secret",
		"auth_value_scrub":   false, // the streaming fast path, as the VPA door's inference connection
		"outbound_allowlist": []string{"127.0.0.0/8"},
	}); err != nil {
		t.Fatal(err)
	}
	role, err := env.Roles.Create("llm-role", []roles.Binding{{ConnectionID: "llm"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := env.Tokens.Create(&tokens.CreateRequest{Name: "t", RoleID: role.ID})
	if err != nil {
		t.Fatal(err)
	}
	cedar := fmt.Sprintf(`permit(principal in Sieve::Role::%q, action, resource in Sieve::Connection::"llm");`, role.ID)
	if _, err := env.IAM.CreatePolicy("allow-llm", "", cedar, true); err != nil {
		t.Fatal(err)
	}
	if err := env.Settings.Set("iam_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	router := api.NewRouter(env.Tokens, env.Connections, env.IAM, env.Registry, env.Roles, env.Approval, env.Audit)
	srv := httptest.NewServer(router.Handler())
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/proxy/llm/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	req.Header.Set("Authorization", "Bearer "+tok.PlaintextToken)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, rerr := io.ReadAll(resp.Body)
	if rerr == nil {
		t.Fatalf("a body cut after the headers ended CLEANLY (%q) -- the agent cannot tell it from a finished answer", body)
	}
	if !strings.Contains(string(body), `"n":0`) {
		t.Fatalf("the bytes before the cut must still be relayed, got %q", body)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("idle cut took %s (limit 300ms)", took)
	}
}
