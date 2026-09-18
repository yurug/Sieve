// VPA-X01 fork: red test for the approval_queue expires_at/executed_at
// additive migration (added alongside the approval TTL + replay-by-id
// features). Written before database.go's migrate() gained the ALTER TABLE
// calls, so it starts red.
package database_test

import (
	"path/filepath"
	"testing"

	"github.com/trilitech/Sieve/internal/database"
)

// TestApprovalQueueTTLMigration asserts a freshly-created database carries
// the expires_at and executed_at columns on approval_queue, and that
// re-opening an already-migrated database (the common restart path) doesn't
// error — the ALTER TABLE must be idempotent.
func TestApprovalQueueTTLMigration(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}

	cols := tableColumns(t, db, "approval_queue")
	for _, col := range []string{"expires_at", "executed_at"} {
		if _, ok := cols[col]; !ok {
			t.Errorf("approval_queue.%s missing", col)
		}
	}
	db.Close()

	// Re-open the same DB file — the ALTER TABLE must tolerate the columns
	// already being present (idempotent migration, no "duplicate column"
	// failure on restart).
	db2, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("re-open db: %v", err)
	}
	defer db2.Close()

	cols2 := tableColumns(t, db2, "approval_queue")
	for _, col := range []string{"expires_at", "executed_at"} {
		if _, ok := cols2[col]; !ok {
			t.Errorf("approval_queue.%s missing after re-open", col)
		}
	}
}
