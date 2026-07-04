// fsync_fail_test.go
// Verifies that a failed fsync during Logger.Log rolls back the in-memory
// chain state (seq and prevHMAC) so the next successful Log call uses the
// same sequence number (ErrAuditFsyncFailed).
package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var errFakeSync = errors.New("injected fsync failure")

func TestAuditFsyncFailureRollback(t *testing.T) {
	baseDir := t.TempDir()
	// Create a 0700 subdirectory; validateParentDir requires mode 0700.
	dir := filepath.Join(baseDir, "auditlogs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "audit.log")

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 9)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 55)
	}

	l, err := Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	// Inject a failing fsync hook.
	l.fsyncFailHook = func() error { return errFakeSync }

	ctx := context.Background()

	// The failed log call must return ErrAuditFsyncFailed.
	err = l.Log(ctx, Event{Action: ActionRead, Outcome: OutcomeOK})
	if !errors.Is(err, ErrAuditFsyncFailed) {
		t.Fatalf("expected ErrAuditFsyncFailed, got %v", err)
	}

	// In-memory seq must NOT have advanced (rollback).
	l.mu.Lock()
	seqAfterFail := l.seq
	prevHMACAfterFail := l.prevHMAC
	l.mu.Unlock()

	if seqAfterFail != 0 {
		t.Errorf("seq = %d after fsync failure, want 0 (rollback violated)", seqAfterFail)
	}

	// prevHMAC after rollback should be the empty string (initial state).
	if prevHMACAfterFail != "" {
		t.Errorf("prevHMAC = %q after rollback, want empty string", prevHMACAfterFail)
	}

	// Remove the fsync hook so the next call can succeed.
	l.fsyncFailHook = nil

	// The next Log call must succeed and use seq=1 (same as the failed attempt's target).
	// Note: the failed write still appended bytes to the file (write succeeded; only
	// fsync failed). The chain state was not advanced, so the next write reuses seq=1
	// but the file now has two lines (one from the failed write, one from the success).
	// The key invariant is that chain state was NOT advanced — the seq stays at 0 until
	// the successful call increments it to 1.
	if err := l.Log(ctx, Event{Action: ActionWrite, Outcome: OutcomeOK}); err != nil {
		t.Fatalf("second Log (after rollback): %v", err)
	}

	l.mu.Lock()
	seqAfterSuccess := l.seq
	l.mu.Unlock()

	// The successful event uses seq=1 (since seq was rolled back to 0 after failure).
	if seqAfterSuccess != 1 {
		t.Errorf("seq = %d after successful Log, want 1 (rollback must keep seq at 0)", seqAfterSuccess)
	}
}
