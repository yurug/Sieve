package gmail

import (
	"encoding/base64"
	"strings"
	"testing"
)

// TestParseAttachmentsParam_AbsentOrEmpty guards send_email's no-attachment
// behavior: when the param is missing, nil, or an empty array, parsing must
// return (nil, nil) so buildMIMEMessage takes the single-part path unchanged.
func TestParseAttachmentsParam_AbsentOrEmpty(t *testing.T) {
	cases := []map[string]any{
		{},
		{"attachments": nil},
		{"attachments": []any{}},
	}
	for i, params := range cases {
		got, err := parseAttachmentsParam(params)
		if err != nil {
			t.Fatalf("case %d: unexpected error: %v", i, err)
		}
		if got != nil {
			t.Fatalf("case %d: got %#v, want nil", i, got)
		}
	}
}

// TestParseAttachmentsParam_ValidAttachments decodes two valid attachments and
// checks filename/mime_type/decoded bytes make it through untouched.
func TestParseAttachmentsParam_ValidAttachments(t *testing.T) {
	params := map[string]any{
		"attachments": []any{
			map[string]any{
				"filename":       "conversation.md",
				"mime_type":      "text/markdown",
				"content_base64": base64.StdEncoding.EncodeToString([]byte("# hello")),
			},
			map[string]any{
				"filename":       "traces.jsonl",
				"mime_type":      "application/x-ndjson",
				"content_base64": base64.StdEncoding.EncodeToString([]byte(`{"a":1}`)),
			},
		},
	}

	got, err := parseAttachmentsParam(params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d attachments, want 2", len(got))
	}
	if got[0].Filename != "conversation.md" || got[0].MimeType != "text/markdown" || string(got[0].Data) != "# hello" {
		t.Errorf("attachment 0 = %+v", got[0])
	}
	if got[1].Filename != "traces.jsonl" || got[1].MimeType != "application/x-ndjson" || string(got[1].Data) != `{"a":1}` {
		t.Errorf("attachment 1 = %+v", got[1])
	}
}

// TestParseAttachmentsParam_InvalidBase64Rejected proves a malformed
// content_base64 fails the whole parse (nothing is sent) rather than being
// silently dropped or truncated.
func TestParseAttachmentsParam_InvalidBase64Rejected(t *testing.T) {
	params := map[string]any{
		"attachments": []any{
			map[string]any{
				"filename":       "bad.txt",
				"mime_type":      "text/plain",
				"content_base64": "not-valid-base64!!!",
			},
		},
	}
	got, err := parseAttachmentsParam(params)
	if err == nil {
		t.Fatal("expected an error for invalid base64, got nil")
	}
	if got != nil {
		t.Fatalf("expected no attachments on error, got %#v", got)
	}
}

// TestParseAttachmentsParam_RejectsUnsafeFilenames covers every unsafe
// filename shape: path separators, "..", and embedded CR/LF (header
// injection via a value written verbatim into Content-Disposition).
func TestParseAttachmentsParam_RejectsUnsafeFilenames(t *testing.T) {
	unsafe := []string{
		"../etc/passwd",
		"a/b.txt",
		`a\b.txt`,
		"..",
		"foo\r\nBcc: evil@example.com",
		"foo\nbar.txt",
	}
	for _, name := range unsafe {
		params := map[string]any{
			"attachments": []any{
				map[string]any{
					"filename":       name,
					"mime_type":      "text/plain",
					"content_base64": base64.StdEncoding.EncodeToString([]byte("x")),
				},
			},
		}
		if _, err := parseAttachmentsParam(params); err == nil {
			t.Errorf("filename %q: expected rejection, got nil error", name)
		}
	}
}

// TestParseAttachmentsParam_RejectsEmptyOrInjectingMimeType covers a missing
// mime_type and one carrying an embedded CR/LF.
func TestParseAttachmentsParam_RejectsEmptyOrInjectingMimeType(t *testing.T) {
	cases := []string{"", "text/plain\r\nBcc: evil@example.com"}
	for _, mt := range cases {
		params := map[string]any{
			"attachments": []any{
				map[string]any{
					"filename":       "ok.txt",
					"mime_type":      mt,
					"content_base64": base64.StdEncoding.EncodeToString([]byte("x")),
				},
			},
		}
		if _, err := parseAttachmentsParam(params); err == nil {
			t.Errorf("mime_type %q: expected rejection, got nil error", mt)
		}
	}
}

// TestParseAttachmentsParam_TotalSizeCapRejected proves the whole send is
// rejected when the sum of decoded attachment bytes exceeds the cap, rather
// than silently truncating.
func TestParseAttachmentsParam_TotalSizeCapRejected(t *testing.T) {
	big := strings.Repeat("a", maxAttachmentsTotalBytes/2+1)
	params := map[string]any{
		"attachments": []any{
			map[string]any{
				"filename":       "big1.bin",
				"mime_type":      "application/octet-stream",
				"content_base64": base64.StdEncoding.EncodeToString([]byte(big)),
			},
			map[string]any{
				"filename":       "big2.bin",
				"mime_type":      "application/octet-stream",
				"content_base64": base64.StdEncoding.EncodeToString([]byte(big)),
			},
		},
	}
	if _, err := parseAttachmentsParam(params); err == nil {
		t.Fatal("expected the total size cap to reject this send")
	}
}

// TestParseAttachmentsParam_CountCapRejected proves more than
// maxAttachmentCount attachments is rejected outright.
func TestParseAttachmentsParam_CountCapRejected(t *testing.T) {
	items := make([]any, maxAttachmentCount+1)
	for i := range items {
		items[i] = map[string]any{
			"filename":       "f.txt",
			"mime_type":      "text/plain",
			"content_base64": base64.StdEncoding.EncodeToString([]byte("x")),
		}
	}
	params := map[string]any{"attachments": items}
	if _, err := parseAttachmentsParam(params); err == nil {
		t.Fatal("expected the attachment count cap to reject this send")
	}
}
