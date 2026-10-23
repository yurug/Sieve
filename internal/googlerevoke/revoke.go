// Package googlerevoke withdraws a Google OAuth grant at Google when Sieve
// forgets a Google connection (VPA-X01 fork).
//
// Deleting a connection row only removes Sieve's copy of the refresh token;
// the grant stays valid at Google until the account owner removes the app
// or Google expires it. Revoke POSTs the token to Google's revocation
// endpoint (RFC 7009 shape, https://oauth2.googleapis.com/revoke), which
// withdraws the whole grant: the refresh token and every access token minted
// from it.
//
// Invariants:
//   - The token travels only in the POST body. It never appears in a URL, an
//     error string, a log line or an audit row: every error this package
//     returns is a *Failure built from a fixed kind and an HTTP status code,
//     never from a transport error or a response body.
//   - One attempt, no retry. The caller deletes its stored copy whatever the
//     outcome, so nothing is kept around to retry with.
package googlerevoke

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultEndpoint is Google's OAuth 2.0 token revocation endpoint.
const DefaultEndpoint = "https://oauth2.googleapis.com/revoke"

// Outcome is the content-free result of one revocation attempt.
type Outcome string

const (
	// Revoked: Google answered 200; the grant is withdrawn.
	Revoked Outcome = "revoked"
	// AlreadyInvalid: Google answered 400 invalid_token; the token was
	// already revoked or expired, which counts as withdrawn.
	AlreadyInvalid Outcome = "already_invalid"
	// NoToken: the stored config held no token to revoke.
	NoToken Outcome = "no_token"
	// Failed: Google could not be reached or refused; see the *Failure.
	Failed Outcome = "failed"
)

// Withdrawn reports whether the outcome means Google no longer honours the
// grant (or there was none).
func (o Outcome) Withdrawn() bool { return o == Revoked || o == AlreadyInvalid || o == NoToken }

// FailureKind classifies a failed revocation without carrying its content.
type FailureKind string

const (
	FailTransport       FailureKind = "transport"        // network, TLS, timeout
	FailStatus          FailureKind = "status"           // a non-200 answer other than invalid_token
	FailRequest         FailureKind = "request"          // the request could not be built
	FailTokenUnreadable FailureKind = "token_unreadable" // the stored config could not be decrypted
)

// Failure is the typed error of a failed revocation. It holds no token, no
// URL and no response body.
type Failure struct {
	Kind   FailureKind
	Status int // HTTP status for FailStatus, else 0
}

func (f *Failure) Error() string {
	if f.Kind == FailStatus {
		return fmt.Sprintf("google token revocation failed: status %d", f.Status)
	}
	return "google token revocation failed: " + string(f.Kind)
}

// Revoker calls the revocation endpoint. The zero value uses DefaultEndpoint
// and a 10-second client.
type Revoker struct {
	Endpoint string
	Client   *http.Client
}

// Revoke withdraws token at Google. An empty token is NoToken, nil.
func (r *Revoker) Revoke(ctx context.Context, token string) (Outcome, error) {
	if token == "" {
		return NoToken, nil
	}
	endpoint, client := r.Endpoint, r.Client
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	body := url.Values{"token": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return Failed, &Failure{Kind: FailRequest}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return Failed, &Failure{Kind: FailTransport}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusOK:
		return Revoked, nil
	case resp.StatusCode == http.StatusBadRequest && isInvalidToken(raw):
		return AlreadyInvalid, nil
	default:
		return Failed, &Failure{Kind: FailStatus, Status: resp.StatusCode}
	}
}

func isInvalidToken(body []byte) bool {
	var e struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(body, &e) == nil && e.Error == "invalid_token"
}

// TokenFromConfig picks the token to revoke from a Google connection's
// stored config: the refresh token (revoking it withdraws the whole grant),
// else the access token. Empty when neither is present.
func TokenFromConfig(config map[string]any) string {
	tok, _ := config["oauth_token"].(map[string]any)
	if tok == nil {
		return ""
	}
	if s, _ := tok["refresh_token"].(string); s != "" {
		return s
	}
	s, _ := tok["access_token"].(string)
	return s
}
