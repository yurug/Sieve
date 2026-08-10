package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// newDraftBodyReq builds a POST with the given JSON body for parseDraftBody.
func parseBody(t *testing.T, jsonBody string) (map[string]any, int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/gmail/v1/users/me/drafts", strings.NewReader(jsonBody))
	rec := httptest.NewRecorder()
	rt := &Router{}
	params, ok := rt.parseDraftBody(rec, req)
	if !ok {
		return nil, rec.Code, rec.Body.String()
	}
	return params, 200, ""
}

func TestParseDraftBody_RejectsUnknownField(t *testing.T) {
	// The reported footgun: a mistyped/unsupported threading field must 400,
	// not be silently dropped so the caller thinks it threaded a reply.
	_, code, body := parseBody(t, `{"to":["x@y.com"],"subject":"s","body":"b","in_reply_to_message":"m1"}`)
	if code != 400 {
		t.Fatalf("code = %d, want 400 for unknown field", code)
	}
	if !strings.Contains(body, "in_reply_to_message") {
		t.Errorf("error should name the offending field; got %q", body)
	}
}

func TestParseDraftBody_RejectsRaw(t *testing.T) {
	_, code, body := parseBody(t, `{"raw":"AAAA","thread_id":"t1"}`)
	if code != 400 {
		t.Fatalf("code = %d, want 400 for raw", code)
	}
	if !strings.Contains(body, "raw") || !strings.Contains(body, "in_reply_to_message_id") {
		t.Errorf("error should explain raw is unsupported and point at structured fields; got %q", body)
	}
}

func TestParseDraftBody_NormalizesCamelCase(t *testing.T) {
	params, code, _ := parseBody(t, `{"to":["x@y.com"],"threadId":"t1","inReplyToMessageId":"m1"}`)
	if code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	if params["thread_id"] != "t1" {
		t.Errorf("threadId not normalized to thread_id: %v", params)
	}
	if params["in_reply_to_message_id"] != "m1" {
		t.Errorf("inReplyToMessageId not normalized: %v", params)
	}
	if _, present := params["threadId"]; present {
		t.Errorf("camelCase key should not survive into op params: %v", params)
	}
}

func TestParseDraftBody_AcceptsKnownFields(t *testing.T) {
	params, code, _ := parseBody(t, `{"to":["x@y.com"],"cc":["c@y.com"],"bcc":["b@y.com"],"subject":"s","body":"b","in_reply_to_message_id":"m1","references":"<r@x>"}`)
	if code != 200 {
		t.Fatalf("code = %d, want 200", code)
	}
	for _, k := range []string{"to", "cc", "bcc", "subject", "body", "in_reply_to_message_id", "references"} {
		if _, ok := params[k]; !ok {
			t.Errorf("param %q missing after parse: %v", k, params)
		}
	}
}
