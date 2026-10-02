package httpproxy

// Per-call time limits for http_proxy (VPA-X01 fork, 2026-10-02).
//
// Before: one http.Client Timeout of 5 minutes, which in Go is a TOTAL budget that includes
// reading the body, plus a 30 s ResponseHeaderTimeout. A model answer still streaming tokens at
// minute five was cut, and because ProxyHTTP ignored io.Copy's error the agent saw a CLEAN end of
// a chunked response -- indistinguishable from a finished one.
//
// Now:
//   - idle: after the headers, the body may go at most Idle without a single byte (default 120 s,
//     SIEVE_HTTP_PROXY_IDLE_TIMEOUT). A stream that keeps flowing is never cut by this rule.
//   - headers: the upstream gets HeaderWait to send its response headers (default 180 s,
//     SIEVE_HTTP_PROXY_HEADER_TIMEOUT): a non-streamed inference reply sends them only at the end.
//   - ceiling: an absolute backstop per call, body included (default 30 min,
//     SIEVE_HTTP_PROXY_MAX_DURATION), so a trickling upstream cannot hold a call forever.
//   - a body that fails after the headers were sent is logged and returned as ErrUpstreamBodyCut;
//     the API router then aborts the response (http.ErrAbortHandler), so the agent sees a broken
//     stream, never a clean EOF.
//
// Values are Go durations ("120s", "30m") or bare integers meaning seconds; anything unparsable
// or non-positive falls back to the default with a log line.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults for Limits; see the package comment above.
const (
	DefaultIdleTimeout   = 120 * time.Second
	DefaultHeaderTimeout = 180 * time.Second
	DefaultMaxDuration   = 30 * time.Minute
)

// Environment variables read by LimitsFromEnv.
const (
	EnvIdleTimeout   = "SIEVE_HTTP_PROXY_IDLE_TIMEOUT"
	EnvHeaderTimeout = "SIEVE_HTTP_PROXY_HEADER_TIMEOUT"
	EnvMaxDuration   = "SIEVE_HTTP_PROXY_MAX_DURATION"
)

// ErrUpstreamIdle is the cause recorded when the upstream sent no byte for Limits.Idle.
var ErrUpstreamIdle = errors.New("http_proxy: upstream idle timeout")

// ErrUpstreamBodyCut wraps any failure while relaying the body after the status line was
// written. The router must abort the response (panic(http.ErrAbortHandler)) on it.
var ErrUpstreamBodyCut = errors.New("http_proxy: response body cut after headers")

// Limits are http_proxy's per-call time limits.
type Limits struct {
	Idle       time.Duration // max silence between two body bytes, after the headers
	HeaderWait time.Duration // max wait for the response headers
	Max        time.Duration // absolute ceiling per call, body included
}

// LimitsFromEnv reads the three limits from the environment, defaulting each one.
func LimitsFromEnv() Limits {
	return Limits{
		Idle:       envDuration(EnvIdleTimeout, DefaultIdleTimeout),
		HeaderWait: envDuration(EnvHeaderTimeout, DefaultHeaderTimeout),
		Max:        envDuration(EnvMaxDuration, DefaultMaxDuration),
	}
}

func envDuration(name string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	d, err := parseDuration(raw)
	if err != nil || d <= 0 {
		log.Printf("http_proxy: ignoring %s=%q (want a positive duration like 120s or seconds); using %s", name, raw, def)
		return def
	}
	return d
}

func parseDuration(raw string) (time.Duration, error) {
	if n, err := strconv.Atoi(raw); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(raw)
}

// do sends req and arms the idle rule on the body: once the headers are in, every Read that
// yields bytes re-arms a timer; Limits.Idle without one cancels the request (cause
// ErrUpstreamIdle), which makes the pending Read fail.
func (p *ProxyConnector) do(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancelCause(req.Context())
	resp, err := p.client.Do(req.WithContext(ctx))
	if err != nil {
		cancel(nil)
		return nil, err
	}
	resp.Body = newIdleBody(ctx, resp.Body, p.limits.Idle, cancel)
	return resp, nil
}

type idleBody struct {
	ctx    context.Context
	body   io.ReadCloser
	idle   time.Duration
	timer  *time.Timer
	cancel context.CancelCauseFunc
	once   sync.Once
}

func newIdleBody(ctx context.Context, body io.ReadCloser, idle time.Duration, cancel context.CancelCauseFunc) *idleBody {
	b := &idleBody{ctx: ctx, body: body, idle: idle, cancel: cancel}
	b.timer = time.AfterFunc(idle, func() { cancel(ErrUpstreamIdle) })
	return b
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if n > 0 {
		b.timer.Reset(b.idle)
	}
	if err != nil && err != io.EOF && errors.Is(context.Cause(b.ctx), ErrUpstreamIdle) {
		err = fmt.Errorf("%w: no byte for %s", ErrUpstreamIdle, b.idle)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.once.Do(func() { b.timer.Stop() })
	err := b.body.Close()
	b.cancel(nil)
	return err
}

// copyFlushing relays body to w, flushing after every chunk so a token stream reaches the agent
// as it arrives. It returns the first read or write error (io.EOF is success).
func copyFlushing(w http.ResponseWriter, body io.Reader) error {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return fmt.Errorf("write to client: %w", werr)
			}
			if ferr := rc.Flush(); ferr != nil && !errors.Is(ferr, http.ErrNotSupported) {
				return fmt.Errorf("flush to client: %w", ferr)
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return fmt.Errorf("read from upstream: %w", rerr)
		}
	}
}
