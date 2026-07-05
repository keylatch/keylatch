package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
)

// auditLogPath creates a 0700 directory for audit logs and returns the log path.
// validateParentDir requires mode 0700.
func auditLogPath(t *testing.T, dir string) string {
	t.Helper()
	auditDir := filepath.Join(dir, "auditlogs")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir auditlogs: %v", err)
	}
	return filepath.Join(auditDir, "audit.log")
}

func openTestLogger(t *testing.T, dir string) (*audit.Logger, []byte) {
	t.Helper()
	path := auditLogPath(t, dir)
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
	return l, dek
}

func TestOpenNewLog(t *testing.T) {
	dir := t.TempDir()
	l, _ := openTestLogger(t, dir)
	if l == nil {
		t.Fatal("Logger is nil")
	}
}

func TestOpenExistingLog(t *testing.T) {
	dir := t.TempDir()
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 2)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 50)
	}
	path := auditLogPath(t, dir)

	// First open: write some events.
	l1, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open1: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := l1.Log(ctx, audit.Event{
			Action:  audit.ActionRead,
			Outcome: audit.OutcomeOK,
			Path:    "default/test/path",
		}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	l1.Close()

	// Second open: should restore chain state.
	l2, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open2: %v", err)
	}
	defer l2.Close()

	// Write more events — should not fail chain verification.
	if err := l2.Log(ctx, audit.Event{
		Action:  audit.ActionWrite,
		Outcome: audit.OutcomeOK,
	}); err != nil {
		t.Fatalf("Log after reopen: %v", err)
	}
}

func TestLogConcurrent(t *testing.T) {
	dir := t.TempDir()
	l, _ := openTestLogger(t, dir)
	ctx := context.Background()

	var wg sync.WaitGroup
	const goroutines = 10
	const eventsPerGoroutine = 100

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				_ = l.Log(ctx, audit.Event{
					Action:  audit.ActionRead,
					Outcome: audit.OutcomeOK,
					Path:    "concurrent/path",
				})
			}
		}(g)
	}
	wg.Wait()
}

func TestRotateNoWindow(t *testing.T) {
	dir := t.TempDir()
	l, _ := openTestLogger(t, dir)
	ctx := context.Background()

	// Write some events.
	for i := 0; i < 5; i++ {
		if err := l.Log(ctx, audit.Event{Action: audit.ActionRead, Outcome: audit.OutcomeOK}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	if err := l.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// After rotation, both files should not be missing simultaneously.
	path := auditLogPath(t, dir)
	rotated := path + ".1"

	if _, err := os.Stat(path); err != nil {
		t.Errorf("new log file missing after rotate: %v", err)
	}
	if _, err := os.Stat(rotated); err != nil {
		t.Errorf("rotated log file missing: %v", err)
	}
}

func TestSummarize1000Events(t *testing.T) {
	dir := t.TempDir()
	salt := make([]byte, 32)
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 200)
	}
	path := auditLogPath(t, dir)
	l, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	ctx := context.Background()
	const total = 1000
	const readEvents = 600
	const writeEvents = 400

	for i := 0; i < readEvents; i++ {
		l.Log(ctx, audit.Event{Action: audit.ActionRead, Outcome: audit.OutcomeOK})
	}
	for i := 0; i < writeEvents; i++ {
		l.Log(ctx, audit.Event{Action: audit.ActionWrite, Outcome: audit.OutcomeOK})
	}

	sum, err := l.Summarize(audit.SummaryOpts{})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	if sum.TotalEvents != total {
		t.Errorf("TotalEvents = %d, want %d", sum.TotalEvents, total)
	}
	if sum.ByAction[audit.ActionRead] != readEvents {
		t.Errorf("Read events = %d, want %d", sum.ByAction[audit.ActionRead], readEvents)
	}
	if sum.ByAction[audit.ActionWrite] != writeEvents {
		t.Errorf("Write events = %d, want %d", sum.ByAction[audit.ActionWrite], writeEvents)
	}
}

func TestVerifyChainBasic(t *testing.T) {
	dir := t.TempDir()
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 3)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 77)
	}
	path := auditLogPath(t, dir)
	l, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		l.Log(ctx, audit.Event{
			Action:    audit.ActionRead,
			Outcome:   audit.OutcomeOK,
			Timestamp: time.Now(),
		})
	}
	l.Close()

	// Header-only verification (auditDEK=nil).
	report, err := audit.VerifyChain(path, salt, nil)
	if err != nil {
		t.Fatalf("VerifyChain (header-only): %v", err)
	}
	if report.FirstBadLine != 0 {
		t.Errorf("header-only: unexpected bad line %d: %s", report.FirstBadLine, report.FirstBadReason)
	}
	if report.TotalLines != 5 {
		t.Errorf("TotalLines = %d, want 5", report.TotalLines)
	}

	// Full verification (with DEK).
	report2, err := audit.VerifyChain(path, salt, dek)
	if err != nil {
		t.Fatalf("VerifyChain (full): %v", err)
	}
	if report2.FirstBadLine != 0 {
		t.Errorf("full: unexpected bad line %d: %s", report2.FirstBadLine, report2.FirstBadReason)
	}
	if report2.Verified != 5 {
		t.Errorf("Verified = %d, want 5", report2.Verified)
	}
}

func TestCanaryNeverPlaintextInAuditLog(t *testing.T) {
	dir := t.TempDir()
	salt := make([]byte, 32)
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 88)
	}
	path := auditLogPath(t, dir)
	l, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const canary = "KEYLATCH_CANARY_PHASE5_AUDIT_0xDEADBEEF"

	ctx := context.Background()
	l.Log(ctx, audit.Event{
		Action:  audit.ActionRead,
		Outcome: audit.OutcomeOK,
		Extra: map[string]any{
			"_canary_unsafe_key": canary,
		},
	})
	l.Close()

	// The canary must not appear in the raw log file.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if containsBytes(raw, []byte(canary)) {
		t.Error("canary appeared in plaintext in audit log")
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
