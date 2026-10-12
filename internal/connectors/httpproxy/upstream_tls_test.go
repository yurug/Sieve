package httpproxy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trilitech/Sieve/internal/policy"
)

// makeTLSProxy points a proxy connector at a local TLS upstream and makes its
// guarded client trust that upstream's self-signed certificate.
func makeTLSProxy(t *testing.T, ts *httptest.Server) *ProxyConnector {
	t.Helper()
	pc := makeProxy(t, ts, "x-api-key", "sk-real")
	tr, ok := pc.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport is %T, want *http.Transport", pc.client.Transport)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	}
	tr.TLSClientConfig.RootCAs = pool
	return pc
}

func proxyOnce(t *testing.T, pc *ProxyConnector, filters []policy.ResponseFilter) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/proxy/conn/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sieve_tok_test")
	rec := httptest.NewRecorder()
	if _, _, err := pc.ProxyHTTP(rec, req, "/v1/chat/completions", filters); err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	return rec
}

// The header names the leaf key the upstream presented, and an upstream-sent
// copy (a forgery attempt by any hop upstream) never reaches the client.
func TestProxyHTTPReportsUpstreamSpki(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(UpstreamSpkiHeader, "00"+hex.EncodeToString(make([]byte, 31)))
		w.Header().Add(UpstreamSpkiHeader, "forged-second-copy")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: hi\n\n"))
	}))
	defer upstream.Close()
	sum := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
	want := hex.EncodeToString(sum[:])

	pc := makeTLSProxy(t, upstream)
	for _, tc := range []struct {
		name    string
		filters []policy.ResponseFilter
	}{
		{"streaming fast path", nil},
		{"filtered slow path", []policy.ResponseFilter{{RedactPatterns: []string{"never-matches-xyz"}}}},
	} {
		// Two calls per path: the second rides a pooled connection.
		for i := 0; i < 2; i++ {
			rec := proxyOnce(t, pc, tc.filters)
			got := rec.Header().Values(UpstreamSpkiHeader)
			if len(got) != 1 || got[0] != want {
				t.Fatalf("%s call %d: %s = %q, want exactly [%q]", tc.name, i, UpstreamSpkiHeader, got, want)
			}
			if rec.Body.String() != "data: hi\n\n" {
				t.Fatalf("%s call %d: body changed: %q", tc.name, i, rec.Body.String())
			}
		}
	}
}

// A plain-HTTP upstream has no TLS key: the header is omitted, and an
// upstream-sent copy is still stripped.
func TestProxyHTTPOmitsSpkiOnPlainHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(UpstreamSpkiHeader, "forged")
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	rec := proxyOnce(t, makeProxy(t, upstream, "x-api-key", "sk-real"), nil)
	if got := rec.Header().Values(UpstreamSpkiHeader); len(got) != 0 {
		t.Fatalf("plain HTTP: %s = %q, want absent", UpstreamSpkiHeader, got)
	}
}
