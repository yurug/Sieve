package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// VPA-X01 2026-09-25: path.Clean dropped the trailing slash, and PyPI answers /simple/<name> with a
// 301 to /simple/<name>/ -- a redirect loop no client behind the proxy could leave.
func TestProxyHTTPKeepsTrailingSlash(t *testing.T) {
	var got []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	pc := makeProxy(t, upstream, "x-api-key", "sk-real")
	for _, p := range []string{"/simple/tabulate/", "/simple/tabulate", "/", "/a//b/"} {
		req := httptest.NewRequest("GET", "/proxy/conn"+p, nil)
		req.Header.Set("Authorization", "Bearer sieve_tok_test")
		if _, _, err := pc.ProxyHTTP(httptest.NewRecorder(), req, p, nil); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	want := []string{"/simple/tabulate/", "/simple/tabulate", "/", "/a/b/"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("upstream paths = %v, want %v", got, want)
		}
	}
	if _, err := validateProxyPath("/a/../../b/"); err == nil {
		t.Errorf("a traversal with a trailing slash must still be refused")
	}
}
