package googlerevoke

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const secretToken = "1//refresh-SECRET-value"

func TestRevokeOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		outcome Outcome
		failed  bool
	}{
		{"200 revoked", 200, `{}`, Revoked, false},
		{"400 invalid_token counts as withdrawn", 400, `{"error":"invalid_token","error_description":"Token expired or revoked"}`, AlreadyInvalid, false},
		{"400 other is a failure", 400, `{"error":"unsupported_token_type"}`, Failed, true},
		{"503 is a failure", 503, `oops ` + secretToken, Failed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got url.Values
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.RawQuery != "" {
					t.Errorf("token must travel in a POST body only: %s %s", r.Method, r.URL)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
					t.Errorf("content-type %q", ct)
				}
				raw, _ := io.ReadAll(r.Body)
				got, _ = url.ParseQuery(string(raw))
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			out, err := (&Revoker{Endpoint: srv.URL, Client: srv.Client()}).Revoke(context.Background(), secretToken)
			if out != tc.outcome {
				t.Fatalf("outcome %q want %q", out, tc.outcome)
			}
			if got.Get("token") != secretToken {
				t.Error("endpoint did not receive the token")
			}
			if (err != nil) != tc.failed {
				t.Fatalf("err=%v", err)
			}
			if err != nil {
				var f *Failure
				if !errors.As(err, &f) || f.Kind != FailStatus || f.Status != tc.status {
					t.Errorf("want typed status failure, got %#v", err)
				}
				if strings.Contains(err.Error(), secretToken) || strings.Contains(err.Error(), "SECRET") {
					t.Error("error string carries the token")
				}
			}
			if out.Withdrawn() == tc.failed {
				t.Errorf("Withdrawn()=%v for %q", out.Withdrawn(), out)
			}
		})
	}
}

func TestRevokeTransportFailureIsTypedAndContentFree(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := srv.URL + "/revoke?token=" + secretToken // even a URL carrying it must not leak
	srv.Close()
	out, err := (&Revoker{Endpoint: endpoint}).Revoke(context.Background(), secretToken)
	var f *Failure
	if out != Failed || !errors.As(err, &f) || f.Kind != FailTransport {
		t.Fatalf("out=%q err=%#v", out, err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Error("transport error carries the token")
	}
}

func TestRevokeWithoutTokenMakesNoCall(t *testing.T) {
	out, err := (&Revoker{Endpoint: "http://127.0.0.1:1/never"}).Revoke(context.Background(), "")
	if out != NoToken || err != nil {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestTokenFromConfigPrefersRefresh(t *testing.T) {
	for _, tc := range []struct {
		cfg  map[string]any
		want string
	}{
		{map[string]any{"oauth_token": map[string]any{"access_token": "a", "refresh_token": "r"}}, "r"},
		{map[string]any{"oauth_token": map[string]any{"access_token": "a"}}, "a"},
		{map[string]any{"oauth_token": map[string]any{"access_token": "a", "refresh_token": ""}}, "a"},
		{map[string]any{}, ""},
	} {
		if got := TokenFromConfig(tc.cfg); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}
