package gmail

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

// TestBuildMIMEMessage_NoAttachments_Unchanged is the compat/regression test:
// a DraftRequest with no Attachments must still go through the original
// single-part builder and produce byte-for-byte identical output to
// buildSimpleMIMEMessage — attachment support must not perturb the existing
// no-attachment wire format at all.
func TestBuildMIMEMessage_NoAttachments_Unchanged(t *testing.T) {
	req := DraftRequest{
		To:      []string{"x@example.com"},
		Cc:      []string{"y@example.com"},
		Subject: "Hello",
		Body:    "plain body text",
	}

	got, err := buildMIMEMessage(req)
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}
	want := buildSimpleMIMEMessage(req)
	if string(got) != string(want) {
		t.Fatalf("attachment-free buildMIMEMessage diverged from buildSimpleMIMEMessage:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(string(got), "multipart") {
		t.Fatalf("attachment-free message must not be multipart: %s", got)
	}
}

// decodedAttachmentPart base64-decodes a multipart.Part's body (the multipart
// package splits parts but does not apply Content-Transfer-Encoding itself).
func decodedAttachmentPart(t *testing.T, part *multipart.Part) []byte {
	t.Helper()
	raw, err := io.ReadAll(part)
	if err != nil {
		t.Fatalf("reading part body: %v", err)
	}
	cleaned := strings.NewReplacer("\r", "", "\n", "").Replace(string(raw))
	data, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		t.Fatalf("base64-decoding part body: %v", err)
	}
	return data
}

// TestBuildMIMEMessage_WithAttachments_RoundTrips builds a message with two
// attachments and parses it back with net/mail + mime/multipart (the same
// libraries a real recipient's client would use), checking every part's
// filename, content type, and decoded bytes match what went in.
func TestBuildMIMEMessage_WithAttachments_RoundTrips(t *testing.T) {
	req := DraftRequest{
		To:      []string{"x@example.com"},
		Subject: "With attachments",
		Body:    "see attached",
		Attachments: []OutgoingAttachment{
			{Filename: "conversation.md", MimeType: "text/markdown", Data: []byte("# hello\nworld")},
			{Filename: "traces.jsonl", MimeType: "application/x-ndjson", Data: []byte(`{"a":1}` + "\n")},
		},
	}

	raw, err := buildMIMEMessage(req)
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("mime.ParseMediaType: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q, want multipart/mixed", mediaType)
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])

	textPart, err := mr.NextPart()
	if err != nil {
		t.Fatalf("reading text part: %v", err)
	}
	textBody, err := io.ReadAll(textPart)
	if err != nil {
		t.Fatalf("reading text part body: %v", err)
	}
	if string(textBody) != req.Body {
		t.Errorf("text part body = %q, want %q", textBody, req.Body)
	}

	for i, want := range req.Attachments {
		part, err := mr.NextPart()
		if err != nil {
			t.Fatalf("reading attachment part %d: %v", i, err)
		}
		if got := part.FileName(); got != want.Filename {
			t.Errorf("attachment %d filename = %q, want %q", i, got, want.Filename)
		}
		gotCT := part.Header.Get("Content-Type")
		if gotCT != want.MimeType {
			t.Errorf("attachment %d Content-Type = %q, want %q", i, gotCT, want.MimeType)
		}
		if cte := part.Header.Get("Content-Transfer-Encoding"); cte != "base64" {
			t.Errorf("attachment %d Content-Transfer-Encoding = %q, want base64", i, cte)
		}
		gotData := decodedAttachmentPart(t, part)
		if string(gotData) != string(want.Data) {
			t.Errorf("attachment %d decoded bytes = %q, want %q", i, gotData, want.Data)
		}
	}

	if _, err := mr.NextPart(); err != io.EOF {
		t.Errorf("expected exactly %d attachment parts, found an extra one (err=%v)", len(req.Attachments), err)
	}
}

// TestBuildMIMEMessage_AttachmentFilenameWithQuoteIsEscaped proves a filename
// containing a double quote (allowed — only path separators, "..", CR and LF
// are rejected upstream in parseAttachmentsParam) still produces a
// parseable Content-Disposition header.
func TestBuildMIMEMessage_AttachmentFilenameWithQuoteIsEscaped(t *testing.T) {
	req := DraftRequest{
		Subject: "s",
		Body:    "b",
		Attachments: []OutgoingAttachment{
			{Filename: `weird"name.txt`, MimeType: "text/plain", Data: []byte("x")},
		},
	}
	raw, err := buildMIMEMessage(req)
	if err != nil {
		t.Fatalf("buildMIMEMessage: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("mime.ParseMediaType: %v", err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	if _, err := mr.NextPart(); err != nil { // text part
		t.Fatalf("reading text part: %v", err)
	}
	part, err := mr.NextPart()
	if err != nil {
		t.Fatalf("reading attachment part: %v", err)
	}
	if got := part.FileName(); got != `weird"name.txt` {
		t.Errorf("filename = %q, want %q", got, `weird"name.txt`)
	}
}
