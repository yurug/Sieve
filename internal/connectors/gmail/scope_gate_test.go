package gmail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
)

const (
	testReadonly = "https://www.googleapis.com/auth/gmail.readonly"
	testCompose  = "https://www.googleapis.com/auth/gmail.compose"
)

// narrowConfig is a stored config as the connections service hands it to
// Factory: decoded from JSON, so the scope list arrives as []any.
func narrowConfig(t *testing.T, scopes ...string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"email":                "owner@example.com",
		"oauth_token":          map[string]any{"access_token": "test-access", "expiry": "2999-01-01T00:00:00Z"},
		"oauth_profile":        "gmail",
		"oauth_granted_scopes": scopes,
	})
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// On a read+compose grant, every label operation is refused before any call
// to Google, with the typed sentinel the API maps to 501.
func TestScopeGateRefusesModifyOpsOnNarrowGrant(t *testing.T) {
	c, err := Factory(narrowConfig(t, testReadonly, testCompose))
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"add_label", "remove_label", "archive"} {
		_, err := c.Execute(context.Background(), op, map[string]any{"message_id": "m1", "label_id": "L"})
		if !errors.Is(err, connector.ErrOperationNotEnabled) {
			t.Fatalf("%s: want ErrOperationNotEnabled, got %v", op, err)
		}
		if !strings.Contains(err.Error(), "gmail.modify") {
			t.Errorf("%s: reason does not name the missing permission: %v", op, err)
		}
	}
}

func TestScopeGateTable(t *testing.T) {
	set := func(s ...string) map[string]bool {
		m := map[string]bool{}
		for _, x := range s {
			m[x] = true
		}
		return m
	}
	for _, tc := range []struct {
		name    string
		op      string
		granted map[string]bool
		refused bool
	}{
		{"narrow grant, archive", "archive", set(testReadonly, testCompose), true},
		{"narrow grant, read", "read_email", set(testReadonly, testCompose), false},
		{"narrow grant, search", "list_emails", set(testReadonly, testCompose), false},
		{"narrow grant, draft", "create_draft", set(testReadonly, testCompose), false},
		{"narrow grant, send", "send_email", set(testReadonly, testCompose), false},
		{"modify grant, archive", "archive", set(scopeGmailModify), false},
		{"full mail grant, add_label", "add_label", set(scopeGmailFullMail), false},
		{"no record (legacy), archive", "archive", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkScopeGate(tc.op, tc.granted)
			if (err != nil) != tc.refused {
				t.Fatalf("refused=%v, err=%v", tc.refused, err)
			}
		})
	}
}

func TestGrantedScopesFromConfigShapes(t *testing.T) {
	if _, ok := grantedScopesFromConfig(map[string]any{}); ok {
		t.Error("absent record must not gate")
	}
	if _, ok := grantedScopesFromConfig(map[string]any{"oauth_granted_scopes": []any{}}); ok {
		t.Error("empty record must not gate")
	}
	for _, v := range []any{
		[]string{testReadonly, testCompose},
		[]any{testReadonly, testCompose},
		testReadonly + " " + testCompose,
	} {
		got, ok := grantedScopesFromConfig(map[string]any{"oauth_granted_scopes": v})
		if !ok || !got[testReadonly] || !got[testCompose] || len(got) != 2 {
			t.Errorf("%T: got %v ok=%v", v, got, ok)
		}
	}
}
