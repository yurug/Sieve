package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/trilitech/Sieve/internal/connector"
)

// operations is the curated list per contracts/slack.md. Names match
// the contract verbatim; agents see them through MCP as
// `slack_<name>` (multi-connection token) or `<name>` (single-conn).
var operations = []connector.OperationDef{
	{
		Name:        "list_channels",
		Description: "List channels accessible to the bot.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"types":     {Type: "string", Description: "public_channel,private_channel,mpim,im (default public_channel,private_channel)"},
			"cursor":    {Type: "string", Description: "Pagination cursor from a previous response's next_cursor."},
			"page_size": {Type: "int", Description: "Page size 1-100 (default 100)."},
		},
	},
	{
		Name:        "list_users",
		Description: "List members of the workspace.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"cursor":    {Type: "string", Description: "Pagination cursor."},
			"page_size": {Type: "int", Description: "Page size 1-100 (default 100)."},
		},
	},
	{
		Name:        "read_user_profile",
		Description: "Get profile info for a user.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"user": {Type: "string", Description: "Slack user ID (Uxxxxx).", Required: true},
		},
	},
	{
		Name:        "read_channel_history",
		Description: "Read messages from a channel.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"channel":   {Type: "string", Description: "Channel ID (Cxxxxx).", Required: true},
			"cursor":    {Type: "string"},
			"page_size": {Type: "int"},
		},
	},
	{
		Name:        "read_thread",
		Description: "Read a thread of messages.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"channel": {Type: "string", Required: true},
			"ts":      {Type: "string", Description: "Thread parent ts.", Required: true},
		},
	},
	{
		Name:        "search_messages",
		Description: "Search messages across the workspace. Requires a user-token connection (auth_kind=user_token); bot-token connections return operation_not_enabled because Slack's search.messages only accepts user tokens.",
		ReadOnly:    true,
		Params: map[string]connector.ParamDef{
			"query":     {Type: "string", Description: "Slack search query, e.g. \"in:#general from:@alice deploy\".", Required: true},
			"cursor":    {Type: "string", Description: "Pagination cursor from a previous response's next_cursor."},
			"page_size": {Type: "int", Description: "Page size 1-100 (default 100)."},
		},
	},
	{
		Name:        "post_message",
		Description: "Post a message to a channel. Set thread_ts to reply inside an existing thread; blocks/attachments for rich formatting.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"channel":     {Type: "string", Required: true},
			"text":        {Type: "string", Required: true, Description: "Message text (also used as fallback/notification when blocks are set)."},
			"thread_ts":   {Type: "string", Description: "ts of the parent message to reply into; omit to post a new top-level message."},
			"blocks":      {Type: "json", Description: "Block Kit blocks (JSON array); Slack chat.postMessage `blocks`."},
			"attachments": {Type: "json", Description: "Legacy attachments (JSON array); Slack chat.postMessage `attachments`."},
		},
	},
	{
		// Escape hatch: reach any Slack Web API method the curated ops don't
		// model, so a missing field is never a dead end. Still IAM-gated
		// (slack/write). Mirrors github_request / gitlab_request / etc.
		Name:        "slack_request",
		Description: "Call any Slack Web API method directly. `api_method` is the method name (e.g. \"conversations.list\", \"chat.postMessage\"); `params` is an object of that method's arguments (nested objects/arrays are JSON-encoded). `http_method` defaults to POST.",
		ReadOnly:    false,
		Params: map[string]connector.ParamDef{
			"api_method":  {Type: "string", Required: true, Description: "Slack Web API method, e.g. conversations.list"},
			"params":      {Type: "json", Description: "Arguments object for the method"},
			"http_method": {Type: "string", Description: "GET or POST (default POST)"},
		},
	},
}

// execute dispatches to the per-op implementation. Unknown operations
// return a clear error rather than panicking — the API and MCP layers
// turn that into a 4xx for the agent.
func (c *Connector) execute(ctx context.Context, op string, params map[string]any) (any, error) {
	switch op {
	case "list_channels":
		return c.opListChannels(ctx, params)
	case "list_users":
		return c.opListUsers(ctx, params)
	case "read_user_profile":
		return c.opReadUserProfile(ctx, params)
	case "read_channel_history":
		return c.opReadChannelHistory(ctx, params)
	case "read_thread":
		return c.opReadThread(ctx, params)
	case "search_messages":
		return c.opSearchMessages(ctx, params)
	case "post_message":
		return c.opPostMessage(ctx, params)
	case "slack_request":
		return c.opSlackRequest(ctx, params)
	default:
		return nil, fmt.Errorf("slack: unknown operation %q", op)
	}
}

// listValues builds the form for a paginated list_* call. Centralised
// so cursor + page_size translation lives in exactly one place.
func listValues(params map[string]any) url.Values {
	v := url.Values{}
	v.Set("limit", strconv.Itoa(pageSizeFrom(params)))
	if cur := cursorFrom(params); cur != "" {
		v.Set("cursor", cur)
	}
	return v
}

func (c *Connector) opListChannels(ctx context.Context, params map[string]any) (any, error) {
	v := listValues(params)
	if t, ok := params["types"].(string); ok && t != "" {
		v.Set("types", t)
	} else {
		v.Set("types", "public_channel,private_channel")
	}
	resp, err := c.client.post(ctx, "conversations.list", v)
	if err != nil {
		return nil, err
	}
	chans, _ := resp["channels"].([]any)
	return map[string]any{
		"items":       chans,
		"next_cursor": nextCursorFrom(resp),
	}, nil
}

func (c *Connector) opListUsers(ctx context.Context, params map[string]any) (any, error) {
	resp, err := c.client.post(ctx, "users.list", listValues(params))
	if err != nil {
		return nil, err
	}
	members, _ := resp["members"].([]any)
	return map[string]any{
		"items":       members,
		"next_cursor": nextCursorFrom(resp),
	}, nil
}

func (c *Connector) opReadUserProfile(ctx context.Context, params map[string]any) (any, error) {
	user, _ := params["user"].(string)
	if user == "" {
		return nil, fmt.Errorf("slack: read_user_profile requires user")
	}
	v := url.Values{}
	v.Set("user", user)
	resp, err := c.client.post(ctx, "users.profile.get", v)
	if err != nil {
		return nil, err
	}
	return resp["profile"], nil
}

func (c *Connector) opReadChannelHistory(ctx context.Context, params map[string]any) (any, error) {
	channel, _ := params["channel"].(string)
	if channel == "" {
		return nil, fmt.Errorf("slack: read_channel_history requires channel")
	}
	v := listValues(params)
	v.Set("channel", channel)
	resp, err := c.client.post(ctx, "conversations.history", v)
	if err != nil {
		return nil, err
	}
	msgs, _ := resp["messages"].([]any)
	return map[string]any{
		"items":       msgs,
		"next_cursor": nextCursorFrom(resp),
	}, nil
}

func (c *Connector) opReadThread(ctx context.Context, params map[string]any) (any, error) {
	channel, _ := params["channel"].(string)
	ts, _ := params["ts"].(string)
	if channel == "" || ts == "" {
		return nil, fmt.Errorf("slack: read_thread requires channel and ts")
	}
	v := listValues(params)
	v.Set("channel", channel)
	v.Set("ts", ts)
	resp, err := c.client.post(ctx, "conversations.replies", v)
	if err != nil {
		return nil, err
	}
	msgs, _ := resp["messages"].([]any)
	return map[string]any{
		"items":       msgs,
		"next_cursor": nextCursorFrom(resp),
	}, nil
}

// opSearchMessages runs Slack's search.messages — but only on a
// user-token connection. Slack rejects bot tokens on search.* with
// not_allowed_token_type, so a bot connection returns the typed
// connector.ErrOperationNotEnabled sentinel instead of making a doomed
// call. Returning a typed error (rather than a phantom-success map with
// "error" inside) lets the API layer map this to HTTP 501 and the MCP
// layer to a tool-error result, so agent SDKs branch on the status code
// / prefix without inspecting response bodies.
//
// The op stays in the catalog for both identities so an IAM rule that
// grants `search_messages` keeps binding across a re-auth or an identity
// change — the identity gate lives here at execution, not at grant time.
//
// Pagination: search.messages is page-based ({paging:{page,pages}}), not
// cursor-based like the conversations.* methods. We translate Sieve's
// normalized cursor/page_size to Slack's page/count and lift the next
// page number back into next_cursor so the agent-facing shape matches
// every other list_* op.
func (c *Connector) opSearchMessages(ctx context.Context, params map[string]any) (any, error) {
	if c.cfg.AuthKind != KindUserToken {
		return nil, fmt.Errorf("%w: slack search.messages requires a user-token connection (auth_kind=user_token); this connection authenticates as a bot", connector.ErrOperationNotEnabled)
	}
	query, _ := params["query"].(string)
	if query == "" {
		return nil, fmt.Errorf("slack: search_messages requires query")
	}
	v := url.Values{}
	v.Set("query", query)
	v.Set("count", strconv.Itoa(pageSizeFrom(params)))
	page := 1
	if cur := cursorFrom(params); cur != "" {
		// search.messages uses a numeric page-as-cursor. Reject a malformed
		// cursor rather than silently resetting to page 1 — a client that
		// mispassed the cursor would otherwise loop over the first page forever
		// instead of learning it sent a bad value.
		n, err := strconv.Atoi(cur)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("slack: search_messages invalid cursor %q (expected a positive page number from a previous response's next_cursor)", cur)
		}
		page = n
	}
	v.Set("page", strconv.Itoa(page))

	resp, err := c.client.get(ctx, "search.messages", v)
	if err != nil {
		return nil, err
	}
	messages, _ := resp["messages"].(map[string]any)
	matches, _ := messages["matches"].([]any)
	return map[string]any{
		"items":       matches,
		"next_cursor": searchNextCursor(messages, page),
	}, nil
}

// searchNextCursor derives the normalized next_cursor for a
// search.messages response. search.messages reports paging as
// {paging: {page, pages}}; the next cursor is the next page number when
// more pages remain, else "".
func searchNextCursor(messages map[string]any, page int) string {
	paging, ok := messages["paging"].(map[string]any)
	if !ok {
		return ""
	}
	pages := 0
	switch p := paging["pages"].(type) {
	case float64:
		pages = int(p)
	case int:
		pages = p
	}
	if page < pages {
		return strconv.Itoa(page + 1)
	}
	return ""
}

func (c *Connector) opPostMessage(ctx context.Context, params map[string]any) (any, error) {
	channel, _ := params["channel"].(string)
	text, _ := params["text"].(string)
	if channel == "" || text == "" {
		return nil, fmt.Errorf("slack: post_message requires channel and text")
	}
	// Tolerate "#general" / "general" / "C012345" — Slack's
	// chat.postMessage accepts any of the three. Strip a leading "#"
	// so the agent doesn't have to think about it.
	channel = strings.TrimPrefix(channel, "#")

	v := url.Values{}
	v.Set("channel", channel)
	v.Set("text", text)
	// thread_ts turns this into a reply inside an existing thread. Previously
	// dropped, so a "reply" silently posted as a new top-level message.
	if ts, _ := params["thread_ts"].(string); ts != "" {
		v.Set("thread_ts", ts)
	}
	// blocks / attachments are JSON arrays; Slack's form API takes them as a
	// JSON-encoded string. Accept either a pre-encoded string or a structured
	// value decoded from the request JSON.
	if blocks, err := jsonParam(params, "blocks"); err != nil {
		return nil, err
	} else if blocks != "" {
		v.Set("blocks", blocks)
	}
	if att, err := jsonParam(params, "attachments"); err != nil {
		return nil, err
	} else if att != "" {
		v.Set("attachments", att)
	}
	resp, err := c.client.post(ctx, "chat.postMessage", v)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// opSlackRequest forwards a call to an arbitrary Slack Web API method. It's the
// generic escape hatch so an agent isn't blocked when a curated op doesn't model
// a field. Each entry in `params` becomes a form value (nested objects/arrays
// JSON-encoded, matching how Slack accepts blocks/attachments).
func (c *Connector) opSlackRequest(ctx context.Context, params map[string]any) (any, error) {
	method, _ := params["api_method"].(string)
	method = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(method), "/"), "api/")
	if method == "" {
		return nil, fmt.Errorf("slack: slack_request requires api_method (e.g. \"conversations.list\")")
	}

	v := url.Values{}
	if args, ok := params["params"].(map[string]any); ok {
		for k, val := range args {
			switch x := val.(type) {
			case nil:
				// skip
			case string:
				v.Set(k, x)
			case bool:
				v.Set(k, strconv.FormatBool(x))
			default:
				b, err := json.Marshal(x)
				if err != nil {
					return nil, fmt.Errorf("slack: slack_request param %q must be JSON-serialisable: %w", k, err)
				}
				v.Set(k, string(b))
			}
		}
	}

	httpMethod, _ := params["http_method"].(string)
	if strings.EqualFold(strings.TrimSpace(httpMethod), "GET") {
		return c.client.get(ctx, method, v)
	}
	return c.client.post(ctx, method, v)
}

// jsonParam coerces a param to a JSON-encoded string for Slack form fields that
// take JSON (blocks, attachments). A string is passed through (assumed already
// JSON); a structured value (from a decoded JSON request) is marshalled. Returns
// "" when the param is absent.
func jsonParam(params map[string]any, key string) (string, error) {
	switch v := params[key].(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("slack: %s must be valid JSON: %w", key, err)
		}
		return string(b), nil
	}
}
