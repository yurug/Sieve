package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	gmailapi "google.golang.org/api/gmail/v1"
)

// decodeDraftRaw pulls the base64url-encoded MIME out of a Drafts.Create /
// Messages.Send request body and returns it as a string, so a test can assert
// on the actual RFC822 headers the client put on the wire.
func decodeDraftRaw(t *testing.T, rawB64 string) string {
	t.Helper()
	b, err := base64.URLEncoding.DecodeString(rawB64)
	if err != nil {
		t.Fatalf("decode raw MIME: %v", err)
	}
	return string(b)
}

// TestCreateDraft_ThreadingAndThreadID is the regression test for the reported
// bug: a reply draft must carry the parent's In-Reply-To/References headers AND
// be filed under the existing threadId — not start a fresh thread.
func TestCreateDraft_ThreadingAndThreadID(t *testing.T) {
	var sentDraft gmailapi.Draft
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/drafts"):
			if err := json.NewDecoder(r.Body).Decode(&sentDraft); err != nil {
				t.Fatalf("decode draft request: %v", err)
			}
			json.NewEncoder(w).Encode(&gmailapi.Draft{
				Id:      "draft-1",
				Message: &gmailapi.Message{Id: "m-1", ThreadId: "thr-1"},
			})
		default: // the follow-up Messages.Get(full)
			json.NewEncoder(w).Encode(&gmailapi.Message{Id: "m-1", ThreadId: "thr-1"})
		}
	})

	_, err := client.CreateDraft(context.Background(), DraftRequest{
		To:         []string{"x@example.com"},
		Bcc:        []string{"audit@example.com"},
		Subject:    "Re: invoice",
		Body:       "here you go",
		ThreadID:   "thr-1",
		InReplyTo:  "parent@mail.example.com", // bare id — must gain <>
		References: "<root@mail.example.com> parent@mail.example.com",
	})
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}

	if sentDraft.Message == nil || sentDraft.Message.ThreadId != "thr-1" {
		t.Fatalf("draft threadId = %+v, want thr-1 (must attach to the existing thread)", sentDraft.Message)
	}
	mime := decodeDraftRaw(t, sentDraft.Message.Raw)
	for _, want := range []string{
		"In-Reply-To: <parent@mail.example.com>",
		"References: <root@mail.example.com> <parent@mail.example.com>",
		"Bcc: audit@example.com",
		"Subject: Re: invoice",
	} {
		if !strings.Contains(mime, want) {
			t.Errorf("MIME missing %q\n--- got ---\n%s", want, mime)
		}
	}
}

// TestGetReplyContext_DerivesReferencesChain proves the in_reply_to_message_id
// lookup pulls threadId + Message-ID/References/Subject from the parent and
// builds an RFC 5322-correct References chain (parent References + Message-ID).
func TestGetReplyContext_DerivesReferencesChain(t *testing.T) {
	var gotFormat string
	var gotHeaders []string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotFormat = r.URL.Query().Get("format")
		gotHeaders = r.URL.Query()["metadataHeaders"]
		json.NewEncoder(w).Encode(&gmailapi.Message{
			Id:       "parent-1",
			ThreadId: "thr-9",
			Payload: &gmailapi.MessagePart{
				Headers: []*gmailapi.MessagePartHeader{
					{Name: "Subject", Value: "invoice 42"},
					{Name: "Message-ID", Value: "<parent@mail.example.com>"},
					{Name: "References", Value: "<root@mail.example.com>"},
				},
			},
		})
	})

	rc, err := client.GetReplyContext(context.Background(), "parent-1")
	if err != nil {
		t.Fatalf("GetReplyContext: %v", err)
	}
	if gotFormat != "metadata" {
		t.Errorf("format = %q, want metadata (body must not be fetched)", gotFormat)
	}
	if !contains(gotHeaders, "Message-ID") || !contains(gotHeaders, "References") {
		t.Errorf("metadataHeaders = %v, want Message-ID + References", gotHeaders)
	}
	if rc.ThreadID != "thr-9" {
		t.Errorf("ThreadID = %q, want thr-9", rc.ThreadID)
	}
	if rc.MessageID != "<parent@mail.example.com>" {
		t.Errorf("MessageID = %q", rc.MessageID)
	}
	if rc.References != "<root@mail.example.com> <parent@mail.example.com>" {
		t.Errorf("References = %q, want the parent chain with parent Message-ID appended", rc.References)
	}
	if rc.Subject != "invoice 42" {
		t.Errorf("Subject = %q", rc.Subject)
	}
}

// TestGetReplyContext_NoPriorReferences: a first reply (parent has no
// References header) yields References = just the parent's Message-ID.
func TestGetReplyContext_NoPriorReferences(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&gmailapi.Message{
			Id:       "parent-1",
			ThreadId: "thr-9",
			Payload: &gmailapi.MessagePart{
				Headers: []*gmailapi.MessagePartHeader{
					{Name: "Message-ID", Value: "<only@mail.example.com>"},
				},
			},
		})
	})
	rc, err := client.GetReplyContext(context.Background(), "parent-1")
	if err != nil {
		t.Fatalf("GetReplyContext: %v", err)
	}
	if rc.References != "<only@mail.example.com>" {
		t.Errorf("References = %q, want just the parent Message-ID", rc.References)
	}
}

func TestListDrafts_ReturnsStubs(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/drafts"):
			json.NewEncoder(w).Encode(&gmailapi.ListDraftsResponse{
				Drafts: []*gmailapi.Draft{
					{Id: "d-1", Message: &gmailapi.Message{Id: "m-1", ThreadId: "t-1"}},
				},
			})
		default: // per-draft metadata fetch
			json.NewEncoder(w).Encode(&gmailapi.Message{
				Id:       "m-1",
				ThreadId: "t-1",
				Payload: &gmailapi.MessagePart{
					Headers: []*gmailapi.MessagePartHeader{
						{Name: "Subject", Value: "hello"},
						{Name: "To", Value: "x@example.com"},
					},
				},
			})
		}
	})

	drafts, err := client.ListDrafts(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListDrafts: %v", err)
	}
	if len(drafts) != 1 || drafts[0].ID != "d-1" {
		t.Fatalf("drafts = %+v", drafts)
	}
	if drafts[0].Message.Subject != "hello" || drafts[0].Message.ID != "m-1" {
		t.Errorf("draft stub message = %+v", drafts[0].Message)
	}
}

func TestDeleteDraft_IssuesDelete(t *testing.T) {
	var method, path string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	if err := client.DeleteDraft(context.Background(), "d-9"); err != nil {
		t.Fatalf("DeleteDraft: %v", err)
	}
	if method != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", method)
	}
	if !strings.HasSuffix(path, "/drafts/d-9") {
		t.Errorf("path = %q, want .../drafts/d-9", path)
	}
}

func TestNormalizeMessageIDs(t *testing.T) {
	cases := map[string]string{
		"parent@x":          "<parent@x>",
		"<parent@x>":        "<parent@x>",
		"<a@x> b@x":         "<a@x> <b@x>",
		"  <a@x>   <b@x>  ": "<a@x> <b@x>",
		"":                  "",
	}
	for in, want := range cases {
		if got := normalizeMessageIDs(in); got != want {
			t.Errorf("normalizeMessageIDs(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuildMIMEMessage_LegacyReplyToStillThreads guards backward compatibility:
// the old reply_to field (a bare id) still produces In-Reply-To + References.
func TestBuildMIMEMessage_LegacyReplyToStillThreads(t *testing.T) {
	raw, err := buildMIMEMessage(DraftRequest{
		To:      []string{"x@example.com"},
		Subject: "Re: x",
		Body:    "b",
		ReplyTo: "legacy@x",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "In-Reply-To: <legacy@x>") || !strings.Contains(s, "References: <legacy@x>") {
		t.Errorf("legacy reply_to did not thread:\n%s", s)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
