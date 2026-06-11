package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
)

func openPruneTestLogger(t *testing.T) *audit.Logger {
	t.Helper()
	dir := t.TempDir()
	logDir := filepath.Join(dir, "auditlogs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(logDir, "audit.log")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 100)
	}
	l, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// TestPrune_RewritesViaRename verifies Prune removes old entries, keeps new
// ones, and leaves the logger usable for further writes. Regression test for
// the Windows failure where Prune truncated the logger's own O_APPEND handle
// (FILE_APPEND_DATA without FILE_WRITE_DATA → Access is denied); Prune now
// rewrites to a temp file, renames it in, and reopens the handle.
func TestPrune_RewritesViaRename(t *testing.T) {
	l := openPruneTestLogger(t)
	ctx := context.Background()

	oldTime := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := l.Log(ctx, audit.Event{Timestamp: oldTime, Action: audit.ActionRead, Outcome: audit.OutcomeOK}); err != nil {
			t.Fatalf("Log (old): %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := l.Log(ctx, audit.Event{Timestamp: time.Now(), Action: audit.ActionWrite, Outcome: audit.OutcomeOK}); err != nil {
			t.Fatalf("Log (new): %v", err)
		}
	}

	pruned, err := l.Prune(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 3 {
		t.Errorf("Prune removed %d entries, want 3", pruned)
	}

	events, err := l.Scan(audit.SinceOpts{})
	if err != nil {
		t.Fatalf("Scan after prune: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("Scan after prune: got %d events, want 2", len(events))
	}

	// The logger must remain usable: the handle was reopened after rename.
	if err := l.Log(ctx, audit.Event{Timestamp: time.Now(), Action: audit.ActionWrite, Outcome: audit.OutcomeOK}); err != nil {
		t.Fatalf("Log after prune: %v", err)
	}
	events, err = l.Scan(audit.SinceOpts{})
	if err != nil {
		t.Fatalf("Scan after post-prune log: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("after post-prune log: got %d events, want 3", len(events))
	}
}

// TestPrune_PruneAllAndChainReseed prunes every entry and verifies the HMAC
// chain reseeds cleanly so subsequent writes still verify.
func TestPrune_PruneAllAndChainReseed(t *testing.T) {
	l := openPruneTestLogger(t)
	ctx := context.Background()

	oldTime := time.Now().Add(-3 * time.Hour)
	for i := 0; i < 4; i++ {
		if err := l.Log(ctx, audit.Event{Timestamp: oldTime, Action: audit.ActionRead, Outcome: audit.OutcomeOK}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	pruned, err := l.Prune(time.Now())
	if err != nil {
		t.Fatalf("Prune (all): %v", err)
	}
	if pruned != 4 {
		t.Errorf("Prune removed %d, want 4", pruned)
	}

	if err := l.Log(ctx, audit.Event{Timestamp: time.Now(), Action: audit.ActionWrite, Outcome: audit.OutcomeOK}); err != nil {
		t.Fatalf("Log after prune-all: %v", err)
	}
	events, err := l.Scan(audit.SinceOpts{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("got %d events, want 1", len(events))
	}
}
