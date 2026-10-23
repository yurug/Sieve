package httpproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const pathToken = "123456789:AAF-path_credential-DoNotLeak"

func makePathProxy(t *testing.T, target string) *ProxyConnector {
	t.Helper()
	c, err := Factory(map[string]any{
		"target_url":         target,
		"auth_header":        "X-Unused",
		"auth_value":         pathToken,
		"auth_path_prefix":   "/bot{value}",
		"auth_value_scrub":   false, // must be ignored in path-credential mode
		"outbound_allowlist": []string{"127.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*ProxyConnector)
}

// echoUpstream answers with the request URL in the body and in a header, like an
// upstream error page that prints what it was asked for.
func echoUpstream(t *testing.T, seen *[]string, hdrs *[]http.Header) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.URL.EscapedPath())
		if hdrs != nil {
			*hdrs = append(*hdrs, r.Header.Clone())
		}
		w.Header().Set("Location", "https://example.invalid"+r.URL.Path)
		w.WriteHeader(404)
		io.WriteString(w, `{"ok":false,"description":"Not Found: `+r.URL.Path+` token `+pathToken+`"}`)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestPathCredentialPrefixesUpstreamPath(t *testing.T) {
	var seen []string
	var hdrs []http.Header
	pc := makePathProxy(t, echoUpstream(t, &seen, &hdrs).URL)

	req := httptest.NewRequest("POST", "/proxy/telegram/sendMessage", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer sieve_tok_test")
	if _, _, err := pc.ProxyHTTP(httptest.NewRecorder(), req, "/sendMessage", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.Execute(context.Background(), "proxy_request", map[string]any{"method": "GET", "path": "/getMe?x=1"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"/bot" + pathToken + "/sendMessage", "/bot" + pathToken + "/getMe"}
	if len(seen) != 2 || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("upstream paths = %q, want %q", seen, want)
	}
	for _, h := range hdrs {
		for k, vs := range h {
			for _, v := range vs {
				if strings.Contains(v, pathToken) {
					t.Errorf("credential also sent in header %s", k)
				}
			}
		}
	}
}

func TestPathCredentialScrubbedFromResponses(t *testing.T) {
	var seen []string
	pc := makePathProxy(t, echoUpstream(t, &seen, nil).URL)

	// Transparent surface, with no filter passed: the scrub must still run.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/proxy/telegram/sendMessage", nil)
	if _, _, err := pc.ProxyHTTP(rec, req, "/sendMessage", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.Body.String(), pathToken) {
		t.Errorf("ProxyHTTP body leaks the credential: %q", rec.Body.String())
	}
	for k, vs := range rec.Header() {
		for _, v := range vs {
			if strings.Contains(v, pathToken) {
				t.Errorf("ProxyHTTP header %s leaks the credential: %q", k, v)
			}
		}
	}

	// Curated surface.
	res, err := pc.Execute(context.Background(), "proxy_request", map[string]any{"method": "GET", "path": "/getMe"})
	if err != nil {
		t.Fatal(err)
	}
	er := res.(*ExecuteResult)
	if strings.Contains(er.Body, pathToken) || !strings.Contains(er.Body, "[REDACTED]") {
		t.Errorf("Execute body not scrubbed: %q", er.Body)
	}
	for k, v := range er.Headers {
		if strings.Contains(v, pathToken) {
			t.Errorf("Execute header %s leaks the credential: %q", k, v)
		}
	}
	if pc.AuthValueScrubFilter() == nil {
		t.Errorf("auth_value_scrub opt-out must be ignored for a path credential")
	}
}

func TestPathCredentialScrubbedFromErrorsAndLogs(t *testing.T) {
	// Nothing listens on this port: the transport error quotes the request URL.
	dead := httptest.NewServer(http.NotFoundHandler())
	target := dead.URL
	dead.Close()
	pc := makePathProxy(t, target)

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/proxy/telegram/sendMessage", nil)
	_, _, err := pc.ProxyHTTP(rec, req, "/sendMessage", nil)
	if err == nil {
		t.Fatal("expected an upstream error")
	}
	for name, s := range map[string]string{"error": err.Error(), "response": rec.Body.String(), "log": logs.String()} {
		if strings.Contains(s, pathToken) {
			t.Errorf("%s leaks the credential: %q", name, s)
		}
	}
	cause := errors.New("dial " + pathToken)
	if re := pc.redactErr(cause); !errors.Is(re, cause) || strings.Contains(re.Error(), pathToken) {
		t.Errorf("redactErr must hide the credential and keep the cause: %v", re)
	}

	_, err = pc.Execute(context.Background(), "proxy_request", map[string]any{"method": "GET", "path": "/getMe"})
	if err == nil || strings.Contains(err.Error(), pathToken) {
		t.Errorf("Execute error leaks the credential or is nil: %v", err)
	}
	if err := pc.Validate(context.Background()); err == nil || strings.Contains(err.Error(), pathToken) {
		t.Errorf("Validate error leaks the credential or is nil: %v", err)
	}
}

func TestPathCredentialRejectsPrefixEscape(t *testing.T) {
	var seen []string
	ts := echoUpstream(t, &seen, nil)
	pc := makePathProxy(t, ts.URL)

	// escaped = what arrives on the wire after /proxy/telegram; decoded = what the router passes.
	cases := []struct{ name, escaped, decoded string }{
		{"dotdot", "/../bot999:other/sendMessage", "/../bot999:other/sendMessage"},
		{"dotdot inner", "/a/../../getMe", "/a/../../getMe"},
		{"dot segment", "/./getMe", "/./getMe"},
		{"encoded slash", "/..%2fbot999:other%2fsendMessage", "/../bot999:other/sendMessage"},
		{"encoded slash upper", "/x%2Fy", "/x/y"},
		{"encoded dot", "/%2e%2e/getMe", "/../getMe"},
		{"encoded backslash", "/x%5cy", "/x\\y"},
		{"double encoding", "/%252e%252e/getMe", "/%2e%2e/getMe"},
		{"absolute url", "/https://evil.example/x", "/https://evil.example/x"},
		{"scheme relative", "//evil.example/x", "//evil.example/x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", nil)
			req.URL = &url.URL{Path: "/proxy/telegram" + mustUnescape(t, c.escaped), RawPath: "/proxy/telegram" + c.escaped}
			rec := httptest.NewRecorder()
			_, _, err := pc.ProxyHTTP(rec, req, c.decoded, nil)
			if err == nil || rec.Code != http.StatusBadRequest {
				t.Errorf("ProxyHTTP accepted %q (code %d, err %v)", c.escaped, rec.Code, err)
			}
			if _, err := pc.Execute(context.Background(), "proxy_request", map[string]any{"method": "GET", "path": c.escaped}); err == nil {
				t.Errorf("Execute accepted %q", c.escaped)
			}
		})
	}
	// Absolute URLs as the Execute path parameter.
	for _, p := range []string{"https://evil.example/x", "http:/evil", "@evil.example/x"} {
		if _, err := pc.Execute(context.Background(), "proxy_request", map[string]any{"method": "GET", "path": p}); err == nil {
			t.Errorf("Execute accepted %q", p)
		}
	}
	if len(seen) != 0 {
		t.Fatalf("a refused path reached the upstream: %q", seen)
	}

	// A path that names another credential stays under the configured prefix.
	if _, err := pc.Execute(context.Background(), "proxy_request", map[string]any{"method": "GET", "path": "/bot999:other/getMe"}); err != nil {
		t.Fatal(err)
	}
	if want := "/bot" + pathToken + "/bot999:other/getMe"; len(seen) != 1 || seen[0] != want {
		t.Fatalf("upstream path = %q, want %q", seen, want)
	}
}

func mustUnescape(t *testing.T, s string) string {
	t.Helper()
	u, err := url.PathUnescape(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestFactoryValidatesAuthPathPrefix(t *testing.T) {
	base := func(prefix, value string) map[string]any {
		return map[string]any{"target_url": "https://api.example.com", "auth_header": "X-Unused", "auth_value": value, "auth_path_prefix": prefix}
	}
	for _, prefix := range []string{"bot{value}", "/bot", "/bot{value}{value}", "/../{value}", "/b?{value}", "/b/{value}/", "//{value}", "/%2f{value}"} {
		if _, err := Factory(base(prefix, "123:abc")); err == nil {
			t.Errorf("template %q accepted", prefix)
		}
	}
	for _, value := range []string{"a/b", "..", ".", "a b", "a%2fb", "a?b", "a#b"} {
		_, err := Factory(base("/{value}", value))
		if err == nil {
			t.Errorf("value %q accepted", value)
		} else if len(value) > 2 && strings.Contains(err.Error(), value) {
			t.Errorf("error quotes the value: %v", err)
		}
	}
	if _, err := Factory(base("/bot{value}", "123:AA-b_c")); err != nil {
		t.Errorf("Telegram-shaped token refused: %v", err)
	}
	// Header connections are unchanged when the field is empty.
	c, err := Factory(base("", "sk-x"))
	if err != nil || c.(*ProxyConnector).authPathPrefix != "" {
		t.Fatalf("empty template should mean header auth: %v", err)
	}
}
