// Package approval implements a human-in-the-loop approval queue for Sieve.
// When a policy evaluates to "approval_required", the operation is submitted
// to this queue and waits for a human to approve or reject it via the web UI.
// The queue uses a listener pattern for blocking waits: callers (like the REST
// API's executeOperation) call WaitForResolution which blocks on a channel.
// When a human approves/rejects via the web UI, resolve updates the database
// and sends the resolved item through the channel, unblocking the caller.
// Key design decisions:
// - Channels are buffered with capacity 1 so the notify side never blocks
// even if the waiting goroutine has already timed out and stopped listening.
// - Listeners are cleaned up in a defer in WaitForResolution, so timeout
// always removes the channel from the map — no leaked goroutines or channels.
// - The MCP server does NOT use WaitForResolution (it returns immediately
// with an approval ID). Only the synchronous REST API blocks. This avoids
// tying up MCP connections while waiting for human action.
// - The resolve method uses a conditional UPDATE (WHERE status = 'pending')
// to prevent double-resolution races.
package approval

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trilitech/Sieve/internal/database"
)

// Status represents the resolution state of an approval queue item.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// Item represents a single entry in the approval queue.
type Item struct {
	ID           string         `json:"id"`
	TokenID      string         `json:"token_id"`
	ConnectionID string         `json:"connection_id"`
	Operation    string         `json:"operation"`
	RequestData  map[string]any `json:"request_data"`
	Status       Status         `json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
	ResolvedAt   *time.Time     `json:"resolved_at,omitempty"`
	ResolvedBy   string         `json:"resolved_by,omitempty"`

	// ExpiresAt is when a pending item is auto-rejected by ExpireStale
	// (VPA-X01 fork). Nil when the queue's TTL was 0 (disabled) at Submit
	// time, or the item predates the TTL feature.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// ExecutedAt marks the moment an approved item's connector operation was
	// actually run via replay-by-id (VPA-X01 fork; see MarkExecuted). Nil
	// means "not yet redeemed" — including for items approved but never
	// replayed, and for every item that predates this feature.
	ExecutedAt *time.Time `json:"executed_at,omitempty"`
}

// SubmitRequest contains the fields needed to create a new approval queue item.
type SubmitRequest struct {
	TokenID      string
	ConnectionID string
	Operation    string
	RequestData  map[string]any
}

// Queue manages the approval queue, combining database persistence with
// in-memory listener channels. The listeners map enables the blocking
// WaitForResolution pattern: a goroutine registers a channel, and the
// channel receives the resolved item when a human acts on it.
type Queue struct {
	db        *database.DB
	listeners map[string]chan *Item // keyed by approval item ID; buffered(1)
	mu        sync.Mutex            // guards listeners map only, not DB operations

	// ttl is the approval expiry duration in nanoseconds (VPA-X01 fork), 0 =
	// disabled. Read on every Submit and by ExpireStale; written once at
	// startup by the --approval-ttl flag (cmd/sieve/main.go). atomic.Int64
	// rather than a plain field guarded by mu — mu protects the listeners
	// map only, and Submit is a hot path that shouldn't contend on it.
	ttl atomic.Int64

	// webhookURL, when non-empty, receives a best-effort JSON POST on every
	// Submit (VPA-X01 fork's --approval-webhook flag). atomic.Pointer so
	// Submit's read never races SetWebhookURL's one-time startup write.
	webhookURL atomic.Pointer[string]
}

// NewQueue creates a new Queue backed by the given database.
func NewQueue(db *database.DB) *Queue {
	return &Queue{
		db:        db,
		listeners: make(map[string]chan *Item),
	}
}

// generateSecureID returns 32 bytes of cryptographic randomness encoded as
// hex (64 hex chars). This gives 256 bits of entropy — far more than UUIDv4's
// 122 bits — and makes enumeration infeasible.
func generateSecureID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Submit creates a new pending approval item and inserts it into the database.
func (q *Queue) Submit(req *SubmitRequest) (*Item, error) {
	id, err := generateSecureID()
	if err != nil {
		return nil, fmt.Errorf("generate approval ID: %w", err)
	}
	dataJSON, err := json.Marshal(req.RequestData)
	if err != nil {
		return nil, fmt.Errorf("marshal request_data: %w", err)
	}

	now := time.Now().UTC()

	// TTL (VPA-X01 fork): when configured, stamp expires_at so ExpireStale
	// can find this item once it's gone stale. ttl <= 0 means the feature is
	// off — expires_at stays NULL, matching the pre-fork "pending forever
	// until a human acts" behavior.
	ttl := time.Duration(q.ttl.Load())
	var expiresAt *time.Time
	if ttl > 0 {
		t := now.Add(ttl)
		expiresAt = &t
	}

	_, err = q.db.Exec(
		`INSERT INTO approval_queue (id, token_id, connection_id, operation, request_data, status, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, req.TokenID, req.ConnectionID, req.Operation, string(dataJSON), string(StatusPending), now, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert approval item: %w", err)
	}

	item := &Item{
		ID:           id,
		TokenID:      req.TokenID,
		ConnectionID: req.ConnectionID,
		Operation:    req.Operation,
		RequestData:  req.RequestData,
		Status:       StatusPending,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
	}

	q.notifyWebhook(item)

	return item, nil
}

// SetTTL configures how long a submitted item may stay pending before
// ExpireStale rejects it (VPA-X01 fork). 0 (the default, and the behavior of
// every build before this fork) disables expiry entirely: items stay
// pending until a human acts, no matter how long that takes. Called once at
// startup from the --approval-ttl flag; safe to call concurrently with
// Submit/ExpireStale (atomic store/load), though in practice it is only
// ever set before the server starts accepting requests.
func (q *Queue) SetTTL(d time.Duration) {
	q.ttl.Store(int64(d))
}

// SetWebhookURL configures the best-effort notification endpoint Submit
// posts to (VPA-X01 fork's --approval-webhook flag). Empty string (the
// default) disables the webhook — Submit then makes no outbound call at
// all, so a fresh/unconfigured Sieve has zero behavior change from the
// pre-fork queue.
func (q *Queue) SetWebhookURL(url string) {
	q.webhookURL.Store(&url)
}

// notifyWebhook posts a best-effort JSON notification to the configured
// webhook URL when a new item is submitted (VPA-X01 fork), so an external
// paging/chat system can alert a human without polling ListPending. Runs in
// its own goroutine with a 5s timeout and only logs failures — a slow or
// unreachable webhook receiver must never delay or fail the agent's
// request that triggered the Submit.
//
// request_data is deliberately EXCLUDED from the payload. The webhook
// receiver is a third-party system outside Sieve's credential boundary
// (Slack, PagerDuty, ...); the operator who needs the full request body
// reaches it via the admin UI/API using the id below, which stays inside
// Sieve's authenticated surface.
func (q *Queue) notifyWebhook(item *Item) {
	urlPtr := q.webhookURL.Load()
	if urlPtr == nil || *urlPtr == "" {
		return
	}
	url := *urlPtr

	payload, err := json.Marshal(map[string]any{
		"id":            item.ID,
		"token_id":      item.TokenID,
		"connection_id": item.ConnectionID,
		"operation":     item.Operation,
		"created_at":    item.CreatedAt,
		"expires_at":    item.ExpiresAt,
	})
	if err != nil {
		log.Printf("approval webhook: marshal payload for item %s: %v", item.ID, err)
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			log.Printf("approval webhook: build request for item %s: %v", item.ID, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("approval webhook: POST to %s failed for item %s: %v", url, item.ID, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("approval webhook: %s returned status %d for item %s", url, resp.StatusCode, item.ID)
		}
	}()
}

// ExpireStale marks every PENDING item whose created_at is older than the
// queue's configured TTL as rejected (status=rejected, resolved_by=
// "expired") — the VPA-X01 drill flagged that a forgotten approval sat
// "pending" forever, which meant an approval_id from a long-abandoned
// request could still be approved (and, with replay-by-id, executed) months
// later. Called every minute by a background goroutine in cmd/sieve while
// the TTL is configured; a TTL of 0 makes this an unconditional no-op
// (0 items, nil error) so the caller doesn't need to check first.
// Resolved items and not-yet-stale pending items are untouched. Listeners
// blocked in WaitForResolution on an item this call expires are woken
// immediately via notify, same as a human clicking Reject.
func (q *Queue) ExpireStale() (int, error) {
	ttl := time.Duration(q.ttl.Load())
	if ttl <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-ttl)

	// Find the affected ids first so we can wake any WaitForResolution
	// listener for each one — a single UPDATE's RowsAffected doesn't tell us
	// WHICH rows changed, and notify() needs the id to look up the channel.
	rows, err := q.db.Query(
		`SELECT id FROM approval_queue WHERE status = ? AND created_at < ?`,
		string(StatusPending), cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("find stale approvals: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan stale approval id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate stale approvals: %w", err)
	}
	rows.Close()

	if len(ids) == 0 {
		return 0, nil
	}

	now := time.Now().UTC()
	result, err := q.db.Exec(
		`UPDATE approval_queue SET status = ?, resolved_by = ?, resolved_at = ?
		 WHERE status = ? AND created_at < ?`,
		string(StatusRejected), "expired", now, string(StatusPending), cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("expire stale approvals: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("check rows affected: %w", err)
	}

	for _, id := range ids {
		q.notify(id)
	}

	return int(n), nil
}

// SetRequestData overwrites a PENDING item's stored request_data — the
// admin JSON API's edit-then-approve flow (VPA-X01 fork), which lets an
// operator correct a malformed or overly-broad request before approving it
// instead of rejecting outright and making the agent resubmit from scratch.
// Restricted to status='pending' (conditional UPDATE, same double-
// resolution guard as resolve()) so an edit can never land after — or race
// — the item's approval/rejection; the request that actually executes is
// always the one an operator saw and approved.
func (q *Queue) SetRequestData(id string, data map[string]any) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal request_data: %w", err)
	}
	result, err := q.db.Exec(
		`UPDATE approval_queue SET request_data = ? WHERE id = ? AND status = ?`,
		string(dataJSON), id, string(StatusPending),
	)
	if err != nil {
		return fmt.Errorf("update request_data: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("approval item %s not found or already resolved", id)
	}
	return nil
}

// MarkExecuted atomically redeems an approved item's replay token exactly
// once (VPA-X01 fork's replay-by-id: internal/api's executeOperation
// executes the connector op using this item's request_data only after this
// call succeeds). The conditional `WHERE executed_at IS NULL` mirrors
// resolve()'s conditional UPDATE for double-resolution: only the first
// caller's UPDATE affects a row. Returns (true, nil) when this call is the
// one that redeemed it, (false, nil) when it was already executed (a
// racing or repeated replay) — the caller maps false to HTTP 409, never an
// error, since "already executed" is an expected outcome, not a failure.
func (q *Queue) MarkExecuted(id string) (bool, error) {
	now := time.Now().UTC()
	result, err := q.db.Exec(
		`UPDATE approval_queue SET executed_at = ? WHERE id = ? AND executed_at IS NULL`,
		now, id,
	)
	if err != nil {
		return false, fmt.Errorf("mark approval item %s executed: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check rows affected: %w", err)
	}
	return rows == 1, nil
}

// WaitForResolution blocks until the approval item with the given ID is
// resolved (approved or rejected) or the timeout elapses. Returns an error on
// timeout.
func (q *Queue) WaitForResolution(id string, timeout time.Duration) (*Item, error) {
	// Check if already resolved BEFORE registering the listener. This closes
	// the race where Approve/Reject is called between Submit and WaitForResolution.
	item, err := q.Get(id)
	if err == nil && item.Status != StatusPending {
		return item, nil
	}

	// Buffered channel (cap 1): if the item is resolved after timeout but
	// before GC, the notify send won't block or panic.
	ch := make(chan *Item, 1)

	q.mu.Lock()
	q.listeners[id] = ch
	q.mu.Unlock()

	// Check again after registering, in case it was resolved between the
	// first check and the listener registration (double-check pattern).
	item, err = q.Get(id)
	if err == nil && item.Status != StatusPending {
		return item, nil
	}

	// Cleanup on all exit paths (success or timeout) to prevent listener
	// map from growing unboundedly with stale entries.
	defer func() {
		q.mu.Lock()
		delete(q.listeners, id)
		q.mu.Unlock()
	}()

	select {
	case item := <-ch:
		return item, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out waiting for resolution of approval item %s", id)
	}
}

// Approve marks the approval item as approved and notifies any waiting listener.
func (q *Queue) Approve(id string) error {
	return q.resolve(id, StatusApproved)
}

// Reject marks the approval item as rejected and notifies any waiting listener.
func (q *Queue) Reject(id string) error {
	return q.resolve(id, StatusRejected)
}

// resolve sets the status, resolved_at, and resolved_by for the given item,
// then notifies any listener.
func (q *Queue) resolve(id string, status Status) error {
	now := time.Now().UTC()

	// Conditional update: AND status = 'pending' prevents double-resolution.
	// If two admins click approve/reject simultaneously, only the first
	// succeeds; the second gets a "not found or already resolved" error.
	result, err := q.db.Exec(
		`UPDATE approval_queue SET status = ?, resolved_at = ?, resolved_by = ? WHERE id = ? AND status = ?`,
		string(status), now, "user", id, string(StatusPending),
	)
	if err != nil {
		return fmt.Errorf("update approval item: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("approval item %s not found or already resolved", id)
	}

	q.notify(id)
	return nil
}

// ListPending returns all pending approval items ordered by created_at ASC.
func (q *Queue) ListPending() ([]Item, error) {
	rows, err := q.db.Query(
		`SELECT id, token_id, connection_id, operation, request_data, status, created_at, resolved_at, resolved_by, expires_at, executed_at
		 FROM approval_queue WHERE status = ? ORDER BY created_at ASC`,
		string(StatusPending),
	)
	if err != nil {
		return nil, fmt.Errorf("query pending items: %w", err)
	}
	defer rows.Close()

	return scanItems(rows)
}

// ListAll returns all approval items with pagination, ordered by created_at DESC.
func (q *Queue) ListAll(limit, offset int) ([]Item, error) {
	rows, err := q.db.Query(
		`SELECT id, token_id, connection_id, operation, request_data, status, created_at, resolved_at, resolved_by, expires_at, executed_at
		 FROM approval_queue ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("query all items: %w", err)
	}
	defer rows.Close()

	return scanItems(rows)
}

// Get returns a single approval item by ID.
func (q *Queue) Get(id string) (*Item, error) {
	row := q.db.QueryRow(
		`SELECT id, token_id, connection_id, operation, request_data, status, created_at, resolved_at, resolved_by, expires_at, executed_at
		 FROM approval_queue WHERE id = ?`,
		id,
	)

	item, err := scanItem(row)
	if err != nil {
		return nil, fmt.Errorf("get approval item %s: %w", id, err)
	}
	return item, nil
}

// notify fetches the resolved item from the database and sends it to the
// waiting listener channel, if one exists.
func (q *Queue) notify(id string) {
	q.mu.Lock()
	ch, ok := q.listeners[id]
	q.mu.Unlock()

	if !ok {
		return
	}

	item, err := q.Get(id)
	if err != nil {
		return
	}

	// Non-blocking send; the channel is buffered with capacity 1.
	select {
	case ch <- item:
	default:
	}
}

// scanItems reads all rows from a query result into a slice of Item.
func scanItems(rows *sql.Rows) ([]Item, error) {
	var items []Item
	for rows.Next() {
		var (
			item       Item
			dataJSON   string
			status     string
			resolvedAt sql.NullTime
			resolvedBy sql.NullString
			expiresAt  sql.NullTime
			executedAt sql.NullTime
		)

		if err := rows.Scan(
			&item.ID, &item.TokenID, &item.ConnectionID, &item.Operation,
			&dataJSON, &status, &item.CreatedAt, &resolvedAt, &resolvedBy,
			&expiresAt, &executedAt,
		); err != nil {
			return nil, fmt.Errorf("scan approval item: %w", err)
		}

		item.Status = Status(status)

		if resolvedAt.Valid {
			item.ResolvedAt = &resolvedAt.Time
		}
		if resolvedBy.Valid {
			item.ResolvedBy = resolvedBy.String
		}
		if expiresAt.Valid {
			item.ExpiresAt = &expiresAt.Time
		}
		if executedAt.Valid {
			item.ExecutedAt = &executedAt.Time
		}

		if err := json.Unmarshal([]byte(dataJSON), &item.RequestData); err != nil {
			return nil, fmt.Errorf("unmarshal request_data: %w", err)
		}

		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approval items: %w", err)
	}

	return items, nil
}

// scanItem reads a single row into an Item.
func scanItem(row *sql.Row) (*Item, error) {
	var (
		item       Item
		dataJSON   string
		status     string
		resolvedAt sql.NullTime
		resolvedBy sql.NullString
		expiresAt  sql.NullTime
		executedAt sql.NullTime
	)

	if err := row.Scan(
		&item.ID, &item.TokenID, &item.ConnectionID, &item.Operation,
		&dataJSON, &status, &item.CreatedAt, &resolvedAt, &resolvedBy,
		&expiresAt, &executedAt,
	); err != nil {
		return nil, err
	}

	item.Status = Status(status)

	if resolvedAt.Valid {
		item.ResolvedAt = &resolvedAt.Time
	}
	if resolvedBy.Valid {
		item.ResolvedBy = resolvedBy.String
	}
	if expiresAt.Valid {
		item.ExpiresAt = &expiresAt.Time
	}
	if executedAt.Valid {
		item.ExecutedAt = &executedAt.Time
	}

	if err := json.Unmarshal([]byte(dataJSON), &item.RequestData); err != nil {
		return nil, fmt.Errorf("unmarshal request_data: %w", err)
	}

	return &item, nil
}
