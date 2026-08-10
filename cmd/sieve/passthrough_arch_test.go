package main

// Architecture invariant: no connector may be a SILENT dead-end façade.
//
// The failure mode this guards against is the one that hit gmail drafts and
// slack post_message: a curated op models only a subset of the real API, the
// generic API/MCP layers forward the caller's extra fields, and the op silently
// ignores them — so a "reply" looks successful but detaches the thread. The
// durable structural defence is that every connector offers SOME way to reach
// the real API: either a generic `*_request` escape hatch (github_request,
// slack_request, …), or it is a deliberately CURATED connector listed below with
// a reason. A new connector must make that choice consciously — it can't slip in
// as a curated façade with no fallback.
//
// This does not, by itself, prove a curated op declares every real-API field
// (a test can't know the real API). It guarantees the ESCAPE HATCH exists so a
// missing field is never a hard dead end, and it forces every curated-with-no-
// passthrough decision to be reviewed here.

import (
	"strings"
	"testing"

	"github.com/trilitech/Sieve/internal/connector"
)

// curatedNoPassthrough lists connectors that intentionally expose no generic
// `*_request` op. Each needs a reason. Removing a connector's escape hatch, or
// adding a new connector without one, must be a deliberate edit to this map.
var curatedNoPassthrough = map[string]string{
	"google": "Gmail/Drive/Calendar/etc. are curated so the two-stage policy " +
		"pipeline can inspect structured content (recipients, subject, body). A raw " +
		"Google API passthrough would let an agent bypass content filtering, so " +
		"missing fields are added to the curated ops instead of via an escape hatch.",
	"anthropic": "messages_create / messages_count_tokens already forward the " +
		"entire request body to the Anthropic API (minus cost controls) — they ARE " +
		"the passthrough, just not *_request-named.",
	"mcp_proxy": "The `call` op forwards tool name + arguments verbatim to the " +
		"upstream MCP server — every op is a passthrough by construction.",
}

func hasPassthroughOp(ops []connector.OperationDef) bool {
	for _, op := range ops {
		if strings.HasSuffix(op.Name, "_request") {
			return true
		}
	}
	return false
}

func TestConnectors_HaveEscapeHatchOrAreCurated(t *testing.T) {
	for _, reg := range allConnectors(t) {
		typ := reg.meta.Type
		reason, curated := curatedNoPassthrough[typ]
		hasHatch := hasPassthroughOp(reg.meta.Operations)

		switch {
		case hasHatch && curated:
			t.Errorf("connector %q has a *_request escape hatch AND is listed in "+
				"curatedNoPassthrough — remove the stale allow-list entry.", typ)
		case !hasHatch && !curated:
			t.Errorf("connector %q exposes no generic passthrough op (a name ending "+
				"in \"_request\") and is not in curatedNoPassthrough.\n"+
				"A curated connector can silently drop caller fields its ops don't model "+
				"(the gmail-drafts / slack thread_ts bug class). Either add a *_request "+
				"escape hatch so the real API is always reachable, or add %q to "+
				"curatedNoPassthrough with a reason if it is curated on purpose.", typ, typ)
		case curated && reason == "":
			t.Errorf("connector %q is in curatedNoPassthrough with an empty reason — "+
				"document why it has no escape hatch.", typ)
		}
	}
}
