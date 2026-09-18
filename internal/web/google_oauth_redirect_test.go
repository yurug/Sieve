// VPA-X01 fork, item A.7: tests for the post-Google-OAuth-callback redirect
// carrying the connected account's email.
//
// handleOAuthCallback's Google branch calls the REAL oauth2 token endpoint
// and the REAL Gmail API (via google.golang.org/api/gmail/v1) with no
// existing test seam to substitute a fake server — unlike Slack/Notion/
// Asana, which hand-roll their token exchange behind an *EndpointOverride
// var specifically for testability. A quick experiment confirms why: a
// global http.DefaultTransport swap DOES intercept oauth2.Config.Exchange
// (golang.org/x/oauth2 falls back to http.DefaultTransport when no
// *http.Client is threaded through the context), but does NOT intercept
// the Gmail API client's own request (google.golang.org/api's transport
// layer rebuilds its base transport via a Clone() that requires
// http.DefaultTransport to already be a genuine *http.Transport — a fake
// RoundTripper of any other concrete type is silently skipped in favor of
// a fresh real transport, so the profile fetch still hits the real Google
// API and fails auth). Building a real fake-exchange-and-profile
// integration test would need a production-code test seam (e.g. an
// option.WithHTTPClient override analogous to the other providers'
// *EndpointOverride vars), which is out of scope for this item ("nothing
// else changes").
//
// So this file tests googleOAuthSuccessRedirect directly — the exact piece
// of logic that changed, and the only thing a broader HTTP-level test
// could additionally exercise is "handleOAuthCallback calls this function
// with the right two arguments," which the manual code review of the one-
// line call site already covers with total confidence.
package web

import (
	"net/url"
	"strings"
	"testing"
)

// P: the redirect target carries both the connection id and the account
// email as query params, URL-decodable back to their original values.
func TestGoogleOAuthSuccessRedirect(t *testing.T) {
	got := googleOAuthSuccessRedirect("gmail-work", "someone@example.com")
	want := "/connections?connected=gmail-work&account=someone%40example.com"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("redirect target must be a valid URL: %v", err)
	}
	q := u.Query()
	if q.Get("connected") != "gmail-work" {
		t.Errorf("connected = %q, want gmail-work", q.Get("connected"))
	}
	if q.Get("account") != "someone@example.com" {
		t.Errorf("account = %q, want someone@example.com", q.Get("account"))
	}
}

// P: characters that are significant in a query string (+, @, space) still
// round-trip correctly through url.Values.Get — a bare string
// concatenation without url.QueryEscape would corrupt "+" (Gmail's
// plus-addressing) by leaving it ambiguous with an encoded space.
func TestGoogleOAuthSuccessRedirect_EncodesSpecialCharacters(t *testing.T) {
	const email = "alice+work@example.com"
	got := googleOAuthSuccessRedirect("conn one", email)

	if strings.Contains(got, "+work@") {
		t.Fatalf("the '+' in the email must be percent-escaped, not passed through raw: %q", got)
	}

	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("redirect target must be a valid URL: %v", err)
	}
	q := u.Query()
	if q.Get("account") != email {
		t.Errorf("account round-trips to %q, want %q", q.Get("account"), email)
	}
	if q.Get("connected") != "conn one" {
		t.Errorf("connected round-trips to %q, want %q", q.Get("connected"), "conn one")
	}
}
