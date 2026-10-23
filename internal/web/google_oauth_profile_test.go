package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connectors/gmail"
	"github.com/trilitech/Sieve/internal/scriptgen"
	"github.com/trilitech/Sieve/internal/testing/testenv"
	"golang.org/x/oauth2"
)

type googleRoundTrip func(*http.Request) (*http.Response, error)

func (f googleRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockGoogle(t *testing.T, scope, refresh, email string) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = googleRoundTrip(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			body = `{"access_token":"access-from-google","token_type":"Bearer","expires_in":3600,"refresh_token":"` + refresh + `"`
			if scope != "" {
				body += `,"scope":"` + scope + `"`
			}
			body += `}`
		case strings.HasSuffix(r.URL.Path, "/users/me/profile"):
			body = `{"emailAddress":"` + email + `"}`
		default:
			t.Errorf("unexpected Google request path %s", r.URL.Path)
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found")), Header: make(http.Header), Request: r}, nil
		}
		h := make(http.Header)
		h.Set("Content-Type", "application/json")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: h, Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func completeGoogle(t *testing.T, s *Server, env *testenv.Env, state string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=fake&state="+state, nil)
	req.AddCookie(env.SessionCookie())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func profileTestServer(t *testing.T) (*Server, *testenv.Env) {
	t.Helper()
	env := testenv.New(t).WithOperator("test-pass", "test-op")
	env.Registry.Register(gmail.Meta, gmail.Factory)
	s := NewServer(env.Tokens, env.Connections, env.Roles, env.Registry, env.Approval,
		env.Audit, "", env.Settings, scriptgen.NewService(env.Connections, env.Settings),
		env.Keyring, env.DB, "")
	s.SetAuth(env.Operator, env.Session)
	s.SetOAuthClients(OAuthClientConfig{GoogleClientID: "test.apps.googleusercontent.com"})
	t.Cleanup(s.Close)
	return s, env
}

func TestGoogleGrantedScopesProvenance(t *testing.T) {
	required := gmailProfileScopes()
	pair := strings.Join(required, " ")
	for _, tc := range []struct {
		name, scope, source string
		ok                  bool
	}{
		{"omitted means requested", "", "request", true},
		{"token exact", pair, "token", true},
		{"partial", gmailReadonlyScope, "", false},
		{"modify alone is not the pair", "https://www.googleapis.com/auth/gmail.modify", "", false},
		{"old broader grant", pair + " https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive", "token", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := &oauth2.Token{AccessToken: "access"}
			if tc.scope != "" {
				tok = tok.WithExtra(map[string]any{"scope": tc.scope})
			}
			scopes, source, err := googleGrantedScopes(tok, required, required)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v scopes=%v", err, scopes)
			}
			if tc.ok && (source != tc.source || len(scopes) != len(strings.Fields(tc.scope)) && tc.scope != "") {
				t.Errorf("source=%q scopes=%v", source, scopes)
			}
			if tc.scope == "" && (source != "request" || strings.Join(scopes, " ") != pair) {
				t.Errorf("omitted-scope provenance=%q scopes=%v", source, scopes)
			}
		})
	}
}

func TestGoogleOAuthProfileCallbackDurability(t *testing.T) {
	for _, tc := range []struct {
		name, scope string
		accepted    bool
	}{
		{"omitted scope", "", true},
		{"reduced grant", gmailReadonlyScope, false},
		{"broader existing grant", gmailReadonlyScope + " " + gmailComposeScope + " https://www.googleapis.com/auth/gmail.modify", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, env := profileTestServer(t)
			mockGoogle(t, tc.scope, "refresh-1", "owner@example.com")
			s.googleProfileLookup = func(_ *oauth2.Config, _ *oauth2.Token) (string, error) { return "owner@example.com", nil }
			add := profilePost(t, s, env, "/connections/add", url.Values{
				"id": {"mailbox"}, "connector_type": {"google"}, "display_name": {"Mailbox"}, "oauth_profile": {"gmail"},
			})
			if add.Code != http.StatusFound {
				t.Fatalf("add: %d %s", add.Code, add.Body.String())
			}
			u, _ := url.Parse(add.Header().Get("Location"))
			cb := completeGoogle(t, s, env, u.Query().Get("state"))
			if (cb.Code == http.StatusSeeOther) != tc.accepted {
				t.Fatalf("callback=%d body=%s", cb.Code, cb.Body.String())
			}
			conn, err := env.Connections.GetWithConfig("mailbox")
			if !tc.accepted {
				if err == nil {
					t.Errorf("partial grant persisted connection: %v", conn.Config)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if conn.Config["oauth_profile"] != googleProfileGmail {
				t.Errorf("profile=%v", conn.Config["oauth_profile"])
			}
			wantSource := "token"
			if tc.scope == "" {
				wantSource = "request"
			}
			if conn.Config["oauth_scopes_source"] != wantSource {
				t.Errorf("scope source=%v", conn.Config["oauth_scopes_source"])
			}
			if conn.Config["oauth_token"].(map[string]any)["refresh_token"] != "refresh-1" {
				t.Error("refresh token lost")
			}
			if got := len(conn.Config["oauth_granted_scopes"].([]any)); got != len(strings.Fields(tc.scope)) && tc.scope != "" {
				t.Errorf("granted scopes count=%d", got)
			}
		})
	}
}

func TestGoogleLegacyGeneralPartialGrantRemainsAccepted(t *testing.T) {
	s, env := profileTestServer(t)
	mockGoogle(t, gmailReadonlyScope+" "+gmailComposeScope, "legacy-refresh", "owner@example.com")
	s.googleProfileLookup = func(_ *oauth2.Config, _ *oauth2.Token) (string, error) { return "owner@example.com", nil }
	add := profilePost(t, s, env, "/connections/add", url.Values{
		"id": {"legacy"}, "connector_type": {"google"}, "display_name": {"Legacy"},
	})
	if add.Code != http.StatusFound {
		t.Fatalf("legacy add: %d", add.Code)
	}
	u, _ := url.Parse(add.Header().Get("Location"))
	if len(strings.Fields(u.Query().Get("scope"))) != 6 {
		t.Fatal("legacy request changed")
	}
	if cb := completeGoogle(t, s, env, u.Query().Get("state")); cb.Code != http.StatusSeeOther {
		t.Fatalf("legacy partial grant: %d %s", cb.Code, cb.Body.String())
	}
	conn, err := env.Connections.GetWithConfig("legacy")
	if err != nil {
		t.Fatal(err)
	}
	if conn.Config["oauth_profile"] != googleProfileGeneral || conn.Config["oauth_scopes_source"] != "token" {
		t.Errorf("legacy provenance=%v", conn.Config)
	}
}
