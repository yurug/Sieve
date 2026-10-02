package httpproxy

// VPA-X01 fork, 2026-10-02: http_proxy's per-call limits are idle-based (limits.go). These tests
// script a slow inference upstream on a SCALED clock -- 1 s of production time = 10 ms here --
// against the real connector, a real net/http server in front of it (doing what the API router
// does on ErrUpstreamBodyCut) and a real client behind it.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const scale = 10 * time.Millisecond // one production second

// scaledLimits are the production defaults (120 s idle, 180 s headers, 30 min ceiling), scaled.
var scaledLimits = Limits{Idle: 120 * scale, HeaderWait: 180 * scale, Max: 1800 * scale}

// slowUpstream waits headerAfter before its headers, then writes one SSE chunk every `every`
// for `total`, pausing `silence` after the first chunk when silence > 0.
func slowUpstream(t *testing.T, headerAfter, every, total, silence time.Duration) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(headerAfter)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		for i, start := 0, time.Now(); time.Since(start) < total; i++ {
			if _, err := fmt.Fprintf(w, "data: {\"n\":%d}\n\n", i); err != nil {
				return
			}
			_ = rc.Flush()
			if i == 0 && silence > 0 {
				time.Sleep(silence)
			}
			time.Sleep(every)
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(ts.Close)
	return ts
}

// door puts the connector, with limits l, behind a real server that aborts the response on
// ErrUpstreamBodyCut exactly as internal/api's handleProxy does. It returns the door's URL and
// a channel carrying ProxyHTTP's error.
func door(t *testing.T, upstream *httptest.Server, l Limits) (string, <-chan error) {
	t.Helper()
	pc := makeProxy(t, upstream, "x-api-key", "sk-real")
	pc.limits = l
	pc.client = newClient([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, l)
	errs := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, err := pc.ProxyHTTP(w, r, "/v1/chat/completions", nil)
		errs <- err
		if errors.Is(err, ErrUpstreamBodyCut) {
			panic(http.ErrAbortHandler)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, errs
}

func call(t *testing.T, url string) (status int, body string, readErr error) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/v1/chat/completions", strings.NewReader(`{"stream":true}`))
	req.Header.Set("Authorization", "Bearer sieve_tok_test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("door request failed before headers: %v", err)
	}
	defer resp.Body.Close()
	b, rerr := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), rerr
}

// A stream that sends a chunk every 10 s for 6 min -- past the old 5-min TOTAL -- passes whole.
func TestIdleTimeoutLetsAFlowingStreamOutliveTheOldTotal(t *testing.T) {
	t.Parallel()
	up := slowUpstream(t, 0, 10*scale, 360*scale, 0)
	url, errs := door(t, up, scaledLimits)
	status, body, rerr := call(t, url)
	if rerr != nil || status != 200 {
		t.Fatalf("status=%d readErr=%v", status, rerr)
	}
	if !strings.HasSuffix(body, "data: [DONE]\n\n") || strings.Count(body, "data: {") < 30 {
		t.Fatalf("stream incomplete: %d chunks, tail %q", strings.Count(body, "data: {"), body[max(0, len(body)-40):])
	}
	if err := <-errs; err != nil {
		t.Fatalf("ProxyHTTP error on a complete stream: %v", err)
	}
}

// 130 s without a byte (idle limit 120 s) is cut, and the agent sees a BROKEN response.
func TestIdleTimeoutCutsASilentStreamAndAbortsTheResponse(t *testing.T) {
	t.Parallel()
	up := slowUpstream(t, 0, 10*scale, 60*scale, 130*scale)
	url, errs := door(t, up, scaledLimits)
	start := time.Now()
	_, body, rerr := call(t, url)
	if rerr == nil {
		t.Fatalf("a cut stream must surface as a read error, got a clean EOF after %q", body)
	}
	if strings.Contains(body, "[DONE]") || !strings.Contains(body, `"n":0`) {
		t.Fatalf("unexpected body before the cut: %q", body)
	}
	if took := time.Since(start); took < 120*scale || took > 129*scale+500*time.Millisecond {
		t.Fatalf("cut after %s, want ~%s (the idle limit)", took, 120*scale)
	}
	err := <-errs
	if !errors.Is(err, ErrUpstreamBodyCut) || !strings.Contains(err.Error(), ErrUpstreamIdle.Error()) {
		t.Fatalf("ProxyHTTP error = %v, want ErrUpstreamBodyCut naming the idle timeout", err)
	}
}

// Headers after 150 s pass (header wait 180 s); after 190 s they are a 502.
func TestHeaderWaitIsRaisedTo180s(t *testing.T) {
	t.Parallel()
	url, _ := door(t, slowUpstream(t, 150*scale, scale, scale, 0), scaledLimits)
	if status, body, rerr := call(t, url); status != 200 || rerr != nil || !strings.Contains(body, "[DONE]") {
		t.Fatalf("headers at 150 s: status=%d err=%v body=%q", status, rerr, body)
	}
	url, _ = door(t, slowUpstream(t, 190*scale, scale, scale, 0), scaledLimits)
	if status, body, _ := call(t, url); status != http.StatusBadGateway || !strings.Contains(body, "timeout awaiting response headers") {
		t.Fatalf("headers at 190 s: status=%d body=%q, want 502 header timeout", status, body)
	}
}

// The absolute ceiling still ends a stream that never stops flowing, as a broken response.
func TestCeilingIsABackstop(t *testing.T) {
	t.Parallel()
	l := scaledLimits
	l.Max = 100 * scale
	url, errs := door(t, slowUpstream(t, 0, 10*scale, 1000*scale, 0), l)
	if _, body, rerr := call(t, url); rerr == nil || strings.Contains(body, "[DONE]") {
		t.Fatalf("a stream past the ceiling must be cut as an error, got err=%v", rerr)
	}
	if err := <-errs; !errors.Is(err, ErrUpstreamBodyCut) {
		t.Fatalf("ProxyHTTP error = %v, want ErrUpstreamBodyCut", err)
	}
}

func TestLimitsFromEnv(t *testing.T) {
	for _, n := range []string{EnvIdleTimeout, EnvHeaderTimeout, EnvMaxDuration} {
		t.Setenv(n, "")
	}
	if got := LimitsFromEnv(); got != (Limits{Idle: 120 * time.Second, HeaderWait: 180 * time.Second, Max: 30 * time.Minute}) {
		t.Fatalf("defaults = %+v", got)
	}
	t.Setenv(EnvIdleTimeout, "90s")
	t.Setenv(EnvHeaderTimeout, "240")
	t.Setenv(EnvMaxDuration, "1h")
	if got := LimitsFromEnv(); got != (Limits{Idle: 90 * time.Second, HeaderWait: 240 * time.Second, Max: time.Hour}) {
		t.Fatalf("overrides = %+v", got)
	}
	t.Setenv(EnvIdleTimeout, "soon")
	t.Setenv(EnvMaxDuration, "-5")
	if got := LimitsFromEnv(); got.Idle != DefaultIdleTimeout || got.Max != DefaultMaxDuration {
		t.Fatalf("invalid values must fall back to defaults, got %+v", got)
	}
	t.Setenv(EnvIdleTimeout, "")
	t.Setenv(EnvMaxDuration, "")
	up := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(up.Close)
	pc := makeProxy(t, up, "x-api-key", "k")
	if pc.limits.Idle != DefaultIdleTimeout || pc.client.Timeout != DefaultMaxDuration {
		t.Fatalf("Factory must apply the env limits: %+v, client timeout %s", pc.limits, pc.client.Timeout)
	}
}
