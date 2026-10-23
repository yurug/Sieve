package audit_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trilitech/Sieve/internal/audit"
	"github.com/trilitech/Sieve/internal/testing/testenv"
)

func insertAged(t *testing.T, env *testenv.Env, op string, ageDays int) {
	t.Helper()
	_, err := env.DB.Exec(`
		INSERT INTO audit_log (token_id, token_name, connection_id, operation, params, policy_result, timestamp)
		VALUES ('tok', 'tok', 'conn', ?, '{"query":"from:someone"}', 'allow', datetime('now', ?))`,
		op, fmt.Sprintf("-%d days", ageDays))
	if err != nil {
		t.Fatal(err)
	}
}

func remainingOps(t *testing.T, env *testenv.Env) map[string]bool {
	t.Helper()
	entries, err := env.Audit.List(nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Operation] = true
	}
	return got
}

// Rows older than the window go; rows inside it stay, at start and on every
// later tick.
func TestRunRetentionPurgesOnlyRowsOlderThanWindow(t *testing.T) {
	env := testenv.New(t)
	insertAged(t, env, "old-31d", 31)
	insertAged(t, env, "old-45d", 45)
	insertAged(t, env, "recent-29d", 29)
	insertAged(t, env, "today", 0)

	var mu sync.Mutex
	var lines []string
	logf := func(f string, a ...any) { mu.Lock(); lines = append(lines, fmt.Sprintf(f, a...)); mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		env.Audit.RunRetention(ctx, audit.DefaultRetentionDays, 20*time.Millisecond, logf)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := remainingOps(t, env); !got["old-31d"] && !got["old-45d"] {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := remainingOps(t, env)
	if got["old-31d"] || got["old-45d"] || !got["recent-29d"] || !got["today"] {
		t.Fatalf("after first sweep: %v", got)
	}

	// A row that ages past the window later is purged by a later tick.
	insertAged(t, env, "late-40d", 40)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && remainingOps(t, env)["late-40d"] {
		time.Sleep(5 * time.Millisecond)
	}
	if remainingOps(t, env)["late-40d"] {
		t.Fatal("periodic sweep did not run")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunRetention did not stop on cancel")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range lines {
		if strings.Contains(l, "someone") {
			t.Errorf("retention log line carries row content: %q", l)
		}
	}
	if len(lines) == 0 || !strings.Contains(lines[0], "older than 30 day") {
		t.Errorf("purge not logged: %v", lines)
	}
}

func TestValidateRetentionDays(t *testing.T) {
	for _, d := range []int{0, -1} {
		if audit.ValidateRetentionDays(d) == nil {
			t.Errorf("%d accepted", d)
		}
	}
	for _, d := range []int{1, 30, 3650} {
		if err := audit.ValidateRetentionDays(d); err != nil {
			t.Errorf("%d refused: %v", d, err)
		}
	}
	if audit.DefaultRetentionDays != 30 {
		t.Errorf("default is %d, documented as 30", audit.DefaultRetentionDays)
	}
}
