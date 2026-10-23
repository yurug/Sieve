package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/testing/testenv"
	"golang.org/x/oauth2"
)

func TestGoogleOAuthProfileReauthKeepsIdentityAndRefresh(t *testing.T) {
	s, env := profileTestServer(t)
	if err := env.Connections.Add("mailbox", "google", "Mailbox", map[string]any{
		"email": "owner@example.com", "oauth_profile": googleProfileGeneral,
		"client_id": "original.apps.googleusercontent.com", "client_secret": "original-secret",
		"oauth_token": map[string]any{"access_token": "old", "refresh_token": "old-refresh"},
	}); err != nil {
		t.Fatal(err)
	}
	email := "owner@example.com"
	s.googleProfileLookup = func(_ *oauth2.Config, _ *oauth2.Token) (string, error) { return email, nil }
	start := func() string {
		rec := profilePost(t, s, env, "/connections/mailbox/reauth", url.Values{"oauth_profile": {"gmail"}})
		if rec.Code != http.StatusFound {
			t.Fatalf("reauth start: %d %s", rec.Code, rec.Body.String())
		}
		u, _ := url.Parse(rec.Header().Get("Location"))
		if strings.Join(strings.Fields(u.Query().Get("scope")), " ") != gmailReadonlyScope+" "+gmailComposeScope {
			t.Fatal("legacy reauth was not narrowed")
		}
		return u.Query().Get("state")
	}
	read := func() map[string]any {
		conn, err := env.Connections.GetWithConfig("mailbox")
		if err != nil {
			t.Fatal(err)
		}
		return conn.Config
	}
	mockGoogle(t, "https://www.googleapis.com/auth/gmail.readonly", "new-refresh", email)
	if rec := completeGoogle(t, s, env, start()); rec.Code != http.StatusForbidden {
		t.Errorf("partial grant: %d", rec.Code)
	}
	if read()["oauth_profile"] != googleProfileGeneral {
		t.Error("partial reauth replaced legacy config")
	}
	mockGoogle(t, gmailReadonlyScope+" "+gmailComposeScope, "new-refresh", email)
	email = "other@example.com"
	if rec := completeGoogle(t, s, env, start()); rec.Code != http.StatusBadRequest {
		t.Errorf("identity swap: %d", rec.Code)
	}
	if read()["oauth_profile"] != googleProfileGeneral {
		t.Error("identity mismatch replaced legacy config")
	}
	email = "owner@example.com"
	mockGoogle(t, gmailReadonlyScope+" "+gmailComposeScope, "", email)
	changed := profilePost(t, s, env, "/connections/mailbox/reauth", url.Values{
		"oauth_profile": {"gmail"}, "google_client_id": {"different.apps.googleusercontent.com"},
	})
	if changed.Code != http.StatusFound {
		t.Fatalf("changed client start: %d", changed.Code)
	}
	changedURL, _ := url.Parse(changed.Header().Get("Location"))
	if rec := completeGoogle(t, s, env, changedURL.Query().Get("state")); rec.Code != http.StatusBadRequest {
		t.Errorf("new client without refresh: %d", rec.Code)
	}
	if read()["client_id"] != "original.apps.googleusercontent.com" {
		t.Error("new client inherited stale refresh token")
	}
	mockGoogle(t, gmailReadonlyScope+" "+gmailComposeScope, "", email)
	if rec := completeGoogle(t, s, env, start()); rec.Code != http.StatusSeeOther {
		t.Fatalf("reauth: %d %s", rec.Code, rec.Body.String())
	}
	config := read()
	if config["oauth_profile"] != googleProfileGmail || config["client_id"] != "original.apps.googleusercontent.com" ||
		config["oauth_token"].(map[string]any)["refresh_token"] != "old-refresh" {
		t.Errorf("reauth lost profile/client/refresh: %v", config)
	}
}

func profilePost(t *testing.T, s *Server, env *testenv.Env, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", env.CSRFToken())
	req.AddCookie(env.SessionCookie())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestGoogleOAuthProfileScopesAndReauth(t *testing.T) {
	s, env := profileTestServer(t)
	add := func(id, profile string) *httptest.ResponseRecorder {
		return profilePost(t, s, env, "/connections/add", url.Values{
			"id": {id}, "connector_type": {"google"}, "display_name": {id}, "oauth_profile": {profile},
		})
	}
	for _, tc := range []struct {
		id, profile string
		count       int
	}{
		{"gmail-only", "gmail", 2}, {"legacy", "", 6},
	} {
		rec := add(tc.id, tc.profile)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s: %d %s", tc.id, rec.Code, rec.Body.String())
		}
		u, _ := url.Parse(rec.Header().Get("Location"))
		scopes := strings.Fields(u.Query().Get("scope"))
		if len(scopes) != tc.count {
			t.Errorf("%s: scopes=%v", tc.id, scopes)
		}
		if tc.profile == "gmail" && strings.Join(scopes, " ") != gmailReadonlyScope+" "+gmailComposeScope {
			t.Errorf("gmail-only URL requested other Google services: %v", scopes)
		}
		if u.Query().Get("code_challenge") == "" || u.Query().Get("state") == "" {
			t.Errorf("%s missing PKCE/state", tc.id)
		}
	}
	if rec := add("unknown", "calendar"); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown profile: %d", rec.Code)
	}
	if exists, _ := env.Connections.Exists("unknown"); exists {
		t.Error("unknown profile persisted")
	}
	for _, tc := range []struct {
		id, profile string
		count       int
	}{
		{"saved-gmail", "gmail", 2}, {"saved-legacy", "", 6},
	} {
		config := map[string]any{"email": tc.id + "@example.com", "client_id": "test.apps.googleusercontent.com"}
		if tc.profile != "" {
			config["oauth_profile"] = tc.profile
		}
		if err := env.Connections.Add(tc.id, "google", tc.id, config); err != nil {
			t.Fatal(err)
		}
		rec := profilePost(t, s, env, "/connections/"+tc.id+"/reauth", url.Values{})
		if rec.Code != http.StatusFound {
			t.Fatalf("reauth %s: %d %s", tc.id, rec.Code, rec.Body.String())
		}
		u, _ := url.Parse(rec.Header().Get("Location"))
		if got := len(strings.Fields(u.Query().Get("scope"))); got != tc.count {
			t.Errorf("reauth %s scopes=%d want %d", tc.id, got, tc.count)
		}
	}
	// A new explicit Gmail consent may narrow a legacy connection's next
	// requested scope set, while an ordinary Sieve reauth remains general.
	rec := profilePost(t, s, env, "/connections/saved-legacy/reauth", url.Values{"oauth_profile": {"gmail"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("explicit Gmail reauth: %d %s", rec.Code, rec.Body.String())
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	if scopes := strings.Fields(u.Query().Get("scope")); strings.Join(scopes, " ") != gmailReadonlyScope+" "+gmailComposeScope {
		t.Errorf("explicit Gmail reauth scopes=%v", scopes)
	}
}
