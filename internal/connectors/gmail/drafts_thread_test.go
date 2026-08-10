package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gmailclient "github.com/trilitech/Sieve/internal/gmail"
	gmailapi "google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// newConnectorWithMock wires a GoogleConnector's gmail client to an httptest
// server, so a test can drive Execute() end-to-end against canned Gmail
// responses.
func newConnectorWithMock(t *testing.T, handler http.HandlerFunc) *GoogleConnector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	svc, err := gmailapi.NewService(context.Background(),
		option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return &GoogleConnector{client: gmailclient.NewClient(svc, "me@example.com")}
}

// TestCreateDraft_InReplyToMessageID is the end-to-end test for the headline
// fix: create_draft with only in_reply_to_message_id set must look up the
// parent, then produce a draft that (a) is filed under the parent's threadId,
// (b) carries In-Reply-To/References, and (c) gets a "Re:" subject derived from
// the parent when none was supplied.
func TestCreateDraft_InReplyToMessageID(t *testing.T) {
	var sentDraft gmailapi.Draft
	g := newConnectorWithMock(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/drafts"):
			_ = json.NewDecoder(r.Body).Decode(&sentDraft)
			json.NewEncoder(w).Encode(&gmailapi.Draft{
				Id: "d-1", Message: &gmailapi.Message{Id: "m-new", ThreadId: "thr-parent"},
			})
		case strings.Contains(r.URL.Path, "/messages/parent-1"):
			// The GetReplyContext metadata lookup.
			json.NewEncoder(w).Encode(&gmailapi.Message{
				Id:       "parent-1",
				ThreadId: "thr-parent",
				Payload: &gmailapi.MessagePart{
					Headers: []*gmailapi.MessagePartHeader{
						{Name: "Subject", Value: "invoice 42"},
						{Name: "Message-ID", Value: "<parent@mail.example.com>"},
						{Name: "References", Value: "<root@mail.example.com>"},
					},
				},
			})
		default: // follow-up full fetch of the created message
			json.NewEncoder(w).Encode(&gmailapi.Message{Id: "m-new", ThreadId: "thr-parent"})
		}
	})

	_, err := g.Execute(context.Background(), "create_draft", map[string]any{
		"to":                     []any{"x@example.com"},
		"body":                   "here you go",
		"in_reply_to_message_id": "parent-1",
	})
	if err != nil {
		t.Fatalf("Execute create_draft: %v", err)
	}

	if sentDraft.Message == nil || sentDraft.Message.ThreadId != "thr-parent" {
		t.Fatalf("draft threadId = %+v, want thr-parent (must not start a new thread)", sentDraft.Message)
	}
	raw, _ := base64.URLEncoding.DecodeString(sentDraft.Message.Raw)
	mime := string(raw)
	for _, want := range []string{
		"In-Reply-To: <parent@mail.example.com>",
		"References: <root@mail.example.com> <parent@mail.example.com>",
		"Subject: Re: invoice 42",
	} {
		if !strings.Contains(mime, want) {
			t.Errorf("MIME missing %q\n--- got ---\n%s", want, mime)
		}
	}
}

func TestEnsureRePrefix(t *testing.T) {
	cases := map[string]string{
		"invoice":     "Re: invoice",
		"Re: invoice": "Re: invoice",
		"RE: invoice": "RE: invoice",
		"re: invoice": "re: invoice",
		"":            "Re: ",
	}
	for in, want := range cases {
		if got := ensureRePrefix(in); got != want {
			t.Errorf("ensureRePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
