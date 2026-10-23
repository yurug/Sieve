package httpproxy

// Path credentials: some upstreams take their credential in the URL path rather
// than in a header (the Telegram Bot API serves /bot<token>/<method>). The
// optional auth_path_prefix field is a template such as "/bot{value}"; the
// connector renders it with auth_value and prepends it to every upstream path.
//
// Invariants:
//   - The prefix is operator-controlled only. The agent's path is appended after
//     it and can neither replace it nor climb out of it: in path-credential mode
//     the agent path may not contain "..", "." segments, percent-encoded
//     separators or dots, double encoding, or an absolute URL.
//   - The credential never reaches the agent or the logs: response bodies are
//     always scrubbed (auth_value_scrub cannot be turned off in this mode),
//     response header values and every error string are redacted.
//   - In this mode the credential is not sent as a header as well.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/trilitech/Sieve/internal/policy"
)

// ErrPathCredentialPath marks an agent path refused in path-credential mode.
var ErrPathCredentialPath = errors.New("http_proxy: path refused for a path-credential connection")

// pathPrefixTemplatePattern: a leading slash, exactly one {value} placeholder,
// and only unreserved path characters around it.
var pathPrefixTemplatePattern = regexp.MustCompile(`^/[A-Za-z0-9_.~/-]*\{value\}[A-Za-z0-9_.~/-]*$`)

// pathCredentialValuePattern: the characters a credential may carry when it is
// placed in a path segment without escaping (a Telegram token is digits, a
// colon, then [A-Za-z0-9_-]).
var pathCredentialValuePattern = regexp.MustCompile(`^[A-Za-z0-9_.~:+=-]+$`)

const redactedMarker = "[REDACTED]"

// renderAuthPathPrefix validates the template and the value and returns the
// rendered prefix ("" when the template is empty). Errors never quote the value.
func renderAuthPathPrefix(template, value string) (string, error) {
	template = strings.TrimSpace(template)
	if template == "" {
		return "", nil
	}
	if !pathPrefixTemplatePattern.MatchString(template) {
		return "", fmt.Errorf("http_proxy: auth_path_prefix %q must start with '/', contain {value} exactly once, and otherwise only [A-Za-z0-9_.~/-]", template)
	}
	if !pathCredentialValuePattern.MatchString(value) {
		return "", fmt.Errorf("http_proxy: auth_value contains characters that cannot be placed in a path (allowed: [A-Za-z0-9_.~:+=-])")
	}
	rendered := strings.Replace(template, "{value}", value, 1)
	if path.Clean(rendered) != rendered {
		return "", fmt.Errorf("http_proxy: auth_path_prefix must render to a clean path (no '.', '..', '//' or trailing '/')")
	}
	return rendered, nil
}

// checkPathCredentialAgentPath refuses an agent path that could reach outside
// the credential prefix. escaped is the path as received on the wire (percent
// encoding intact); decoded is the same path decoded once.
func checkPathCredentialAgentPath(escaped, decoded string) error {
	lower := strings.ToLower(escaped)
	for _, enc := range []string{"%2f", "%5c", "%2e", "%25"} {
		if strings.Contains(lower, enc) {
			return fmt.Errorf("%w: encoded separator, dot or percent", ErrPathCredentialPath)
		}
	}
	if strings.Contains(decoded, "%") {
		return fmt.Errorf("%w: double encoding", ErrPathCredentialPath)
	}
	if !strings.HasPrefix(decoded, "/") || strings.HasPrefix(decoded, "//") || strings.Contains(decoded, "://") {
		return fmt.Errorf("%w: absolute URL", ErrPathCredentialPath)
	}
	if strings.Contains(decoded, "\\") {
		return fmt.Errorf("%w: backslash", ErrPathCredentialPath)
	}
	for _, seg := range strings.Split(decoded, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: dot segment", ErrPathCredentialPath)
		}
	}
	return nil
}

// upstreamURL joins the operator prefix (if any) and the cleaned agent path onto
// the target base, and checks the result stays on the target host and under the
// prefix before any credential is attached.
func (p *ProxyConnector) upstreamURL(targetBase *url.URL, cleaned string) (*url.URL, error) {
	if p.authPathPrefix == "" {
		return targetBase.JoinPath(cleaned), nil
	}
	u := targetBase.JoinPath(p.authPathPrefix, cleaned)
	// JoinPath keeps a relative base relative (an empty base path yields "bot…"
	// without a leading slash); compare both sides in absolute form.
	root := "/" + strings.Trim(targetBase.EscapedPath(), "/") + p.authPathPrefix
	root = strings.Replace(root, "//", "/", 1)
	ep := "/" + strings.TrimPrefix(u.EscapedPath(), "/")
	if u.Scheme != targetBase.Scheme || u.Host != targetBase.Host || (ep != root && !strings.HasPrefix(ep, root+"/")) {
		return nil, fmt.Errorf("%w: resolves outside the credential prefix", ErrPathCredentialPath)
	}
	return u, nil
}

// redact removes the path credential from a string bound for the agent or a log.
// A no-op for header-credential connections.
func (p *ProxyConnector) redact(s string) string {
	if p.authPathPrefix == "" || p.authValue == "" {
		return s
	}
	s = strings.ReplaceAll(s, p.authPathPrefix, redactedMarker)
	s = strings.ReplaceAll(s, p.authValue, redactedMarker)
	if esc := url.PathEscape(p.authValue); esc != p.authValue {
		s = strings.ReplaceAll(s, esc, redactedMarker)
	}
	return s
}

// redactErr wraps err with its message redacted, keeping errors.Is on the cause.
func (p *ProxyConnector) redactErr(err error) error {
	if err == nil || p.authPathPrefix == "" {
		return err
	}
	return &redactedError{msg: p.redact(err.Error()), cause: err}
}

type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// copyResponseHeaders copies upstream response headers to dst, skipping the
// keys skip reports, and redacting values in path-credential mode (a redirect
// Location or a debug header may echo the request URL).
func (p *ProxyConnector) copyResponseHeaders(dst, src http.Header, skip func(string) bool) {
	for key, values := range src {
		if skip != nil && skip(key) {
			continue
		}
		for _, v := range values {
			dst.Add(key, p.redact(v))
		}
	}
}

// ensureScrubFilter guarantees the body scrub runs in path-credential mode even
// for a caller that passed no filters (the router normally prepends it).
func (p *ProxyConnector) ensureScrubFilter(filters []policy.ResponseFilter) []policy.ResponseFilter {
	if p.authPathPrefix == "" {
		return filters
	}
	for _, f := range filters {
		if f.Label == "auth_value_scrubbed" {
			return filters
		}
	}
	if sf := p.AuthValueScrubFilter(); sf != nil {
		return append([]policy.ResponseFilter{*sf}, filters...)
	}
	return filters
}
