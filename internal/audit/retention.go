package audit

import (
	"context"
	"fmt"
	"time"
)

// Audit-log retention (VPA-X01 fork).
//
// Audit rows carry request parameters in clear (a search query, a message
// id, a draft's recipients and body), so they must not live forever.
// RunRetention purges rows older than the configured number of days once at
// start, then on every tick, until ctx is cancelled. `sieve serve` runs it
// with --audit-retention-days (default DefaultRetentionDays) and a daily
// tick. A failed sweep is logged without content and tried again at the
// next tick.

// DefaultRetentionDays is the retention used when the operator sets none.
const DefaultRetentionDays = 30

// RetentionSweepInterval is the production cadence of RunRetention.
const RetentionSweepInterval = 24 * time.Hour

// ValidateRetentionDays refuses a window that would keep nothing or
// everything: 0 and negative values are errors (to keep rows forever an
// operator must say so with a large value, not by accident).
func ValidateRetentionDays(days int) error {
	if days < 1 {
		return fmt.Errorf("audit retention must be at least 1 day (got %d)", days)
	}
	return nil
}

// RunRetention blocks: sweep now, then every interval, until ctx is done.
// logf receives one content-free line per sweep that deleted rows or failed.
func (l *Logger) RunRetention(ctx context.Context, days int, interval time.Duration, logf func(format string, args ...any)) {
	sweep := func() {
		n, err := l.Cleanup(days)
		switch {
		case err != nil:
			logf("audit retention sweep failed (will retry next sweep): %v", err)
		case n > 0:
			logf("audit retention: purged %d audit row(s) older than %d day(s)", n, days)
		}
	}
	sweep()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweep()
		}
	}
}
