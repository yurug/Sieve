package gmail

import (
	"fmt"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// Scope gate (VPA-X01 fork).
//
// A connection authorized under the narrow `gmail` OAuth profile holds
// gmail.readonly + gmail.compose only. Those cover search, read, drafts and
// sends, but not messages.modify, which the label operations need. Without
// this gate such an operation would reach Google and come back as an opaque
// 403 "insufficient authentication scopes". The gate refuses it before any
// network call with connector.ErrOperationNotEnabled (API: 501, MCP:
// "operation_not_enabled:"), naming the missing permission.
//
// The gate only acts when the stored config records the granted scopes
// (`oauth_granted_scopes`, written by the OAuth callback since the scope
// profile change). A connection without that record keeps the historical
// behavior: Sieve does not know what it was granted, so Google decides.

const (
	scopeGmailModify   = "https://www.googleapis.com/auth/gmail.modify"
	scopeGmailFullMail = "https://mail.google.com/"
)

// modifyOps are the Gmail operations that call users.messages.modify, which
// accepts only gmail.modify or the full-mail scope.
var modifyOps = map[string]bool{
	"add_label":    true,
	"remove_label": true,
	"archive":      true,
}

// grantedScopesFromConfig reads the recorded grant. ok=false means no record
// (legacy connection): the gate must not act.
func grantedScopesFromConfig(config map[string]any) (scopes map[string]bool, ok bool) {
	var list []string
	switch v := config["oauth_granted_scopes"].(type) {
	case []string:
		list = v
	case []any:
		for _, s := range v {
			if str, isStr := s.(string); isStr {
				list = append(list, str)
			}
		}
	case string:
		list = strings.Fields(v)
	default:
		return nil, false
	}
	if len(list) == 0 {
		return nil, false
	}
	scopes = make(map[string]bool, len(list))
	for _, s := range list {
		scopes[s] = true
	}
	return scopes, true
}

// checkScopeGate returns a wrapped ErrOperationNotEnabled when op needs a
// permission the recorded grant lacks; nil otherwise.
func checkScopeGate(op string, granted map[string]bool) error {
	if granted == nil || !modifyOps[op] {
		return nil
	}
	if granted[scopeGmailModify] || granted[scopeGmailFullMail] {
		return nil
	}
	return fmt.Errorf("%w: gmail %s needs the gmail.modify permission, which this connection was not granted (it holds read and compose only)", connector.ErrOperationNotEnabled, op)
}
