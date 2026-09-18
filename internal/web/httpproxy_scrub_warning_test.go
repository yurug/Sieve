// VPA-X01 fork: red test for drill finding #12 — operator-visible warning
// when an http_proxy connection is saved with auth_value_scrub enabled.
// shouldWarnAuthValueScrubStreaming is the decision extracted out of the
// log.Printf call site so it's testable without capturing global log
// output (matching this package's existing convention — see
// passphrase_rotation.go's un-captured log.Printf — of logging directly
// via the `log` package rather than an injected logger).
package web

import "testing"

func TestShouldWarnAuthValueScrubStreaming(t *testing.T) {
	cases := []struct {
		name          string
		connectorType string
		cfg           map[string]any
		want          bool
	}{
		{
			name:          "http_proxy, scrub explicitly true",
			connectorType: "http_proxy",
			cfg:           map[string]any{"auth_value_scrub": true},
			want:          true,
		},
		{
			name:          "http_proxy, scrub explicitly false",
			connectorType: "http_proxy",
			cfg:           map[string]any{"auth_value_scrub": false},
			want:          false,
		},
		{
			name:          "http_proxy, scrub absent from cfg (create mode — field is EditOnly) defaults to the factory's true",
			connectorType: "http_proxy",
			cfg:           map[string]any{},
			want:          true,
		},
		{
			name:          "non-http_proxy connector never warns, even with the field present",
			connectorType: "google",
			cfg:           map[string]any{"auth_value_scrub": true},
			want:          false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shouldWarnAuthValueScrubStreaming(c.connectorType, c.cfg)
			if got != c.want {
				t.Errorf("shouldWarnAuthValueScrubStreaming(%q, %v) = %v, want %v", c.connectorType, c.cfg, got, c.want)
			}
		})
	}
}
