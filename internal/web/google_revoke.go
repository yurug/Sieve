package web

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/trilitech/Sieve/internal/googlerevoke"
)

// googleRevokeHeader carries the content-free revocation outcome on the
// connection-delete redirect ("revoked", "already_invalid", "no_token" or
// "failed"), so an admin client learns whether Google still honours the
// grant. The redirect target itself is unchanged (/connections).
const googleRevokeHeader = "X-Sieve-Google-Revoke"

// SetGoogleRevoker overrides the revocation endpoint/client (tests).
func (s *Server) SetGoogleRevoker(r *googlerevoke.Revoker) { s.googleRevoker = r }

// revokeGoogleGrant withdraws the Google grant of connection id before the
// row is deleted (VPA-X01 fork). Returns "" for a non-Google or unknown
// connection, else the outcome. A failure is logged and audited as a typed
// failure (kind and status only, never the token) and is not retried: the
// caller deletes the stored token anyway, so nothing remains to retry with.
func (s *Server) revokeGoogleGrant(ctx context.Context, r *http.Request, id string) string {
	conn, err := s.connections.Get(id)
	if err != nil || conn.ConnectorType != "google" {
		return ""
	}
	var outcome googlerevoke.Outcome
	var rerr error
	full, err := s.connections.GetWithConfig(id)
	if err != nil {
		outcome, rerr = googlerevoke.Failed, &googlerevoke.Failure{Kind: googlerevoke.FailTokenUnreadable}
	} else {
		revoker := s.googleRevoker
		if revoker == nil {
			revoker = &googlerevoke.Revoker{}
		}
		outcome, rerr = revoker.Revoke(ctx, googlerevoke.TokenFromConfig(full.Config))
	}
	params := map[string]any{"outcome": string(outcome)}
	result := "success"
	var f *googlerevoke.Failure
	if errors.As(rerr, &f) {
		params["failure_kind"] = string(f.Kind)
		if f.Status != 0 {
			params["failure_status"] = f.Status
		}
		result = "error"
		log.Printf("connection %s: %v; deleting the stored token anyway", id, f)
	}
	_ = s.audit.LogOperator(operatorDisplayName(r, s), "connection.google_revoke", id, params, result)
	return string(outcome)
}
