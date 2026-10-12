package httpproxy

// Upstream TLS key report (VPA-X01 fork).
//
// The agent behind Sieve cannot see the TLS connection Sieve opens to the
// upstream, so it cannot tell whether that connection ends at the server it
// trusts or at a hop in between (a CDN, a hijacked DNS answer, a corporate
// proxy). When the upstream publishes an attested TLS key, the agent can
// compare it with the key Sieve actually met -- if Sieve reports it.
//
// Contract, on every response of the HTTP proxy surface (streamed or not):
//   - X-Sieve-Upstream-Spki-Sha256 = lowercase hex SHA-256 of the DER
//     SubjectPublicKeyInfo of the leaf certificate presented on the TLS
//     connection that carried THIS request (resp.TLS, pooled or not);
//   - any copy of that header sent by the upstream is removed first, so a hop
//     upstream cannot forge it;
//   - a plain-HTTP upstream gets no header at all (never an empty value).
// Bodies, authorization and audit are unchanged.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// UpstreamSpkiHeader names the response header carrying the upstream leaf key's hash.
const UpstreamSpkiHeader = "X-Sieve-Upstream-Spki-Sha256"

// upstreamSpkiSha256 returns the lowercase hex SHA-256 of the leaf certificate's
// SubjectPublicKeyInfo on the connection that served resp, or "" when the
// response did not come over TLS or no peer certificate was presented.
func upstreamSpkiSha256(resp *http.Response) string {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// setUpstreamTLSHeaders replaces whatever the upstream sent under
// UpstreamSpkiHeader with Sieve's own measurement. Call it after the upstream
// headers are copied into dst and before the status line is written.
func setUpstreamTLSHeaders(dst http.Header, resp *http.Response) {
	dst.Del(UpstreamSpkiHeader)
	if spki := upstreamSpkiSha256(resp); spki != "" {
		dst.Set(UpstreamSpkiHeader, spki)
	}
}
