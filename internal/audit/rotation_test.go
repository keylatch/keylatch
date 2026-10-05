package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	audithmac "github.com/keylatch/keylatch/internal/audit/hmac"
)

func openSmallLog(t *testing.T, maxSize int64, retain int) (*Logger, string, []byte) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cfg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.log")
	salt := make([]byte, 32)
	dek := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 3)
		dek[i] = byte(i + 50)
	}
	l, err := Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	l.maxSize = maxSize
	l.retainFiles = retain
	return l, path, salt
}

func lastLine(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	return lines[len(lines)-1]
}

func firstEventExtra(t *testing.T, path string, dek []byte) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(data), "\n")
	e, ok := decodeAuditLine(line, dek)
	if !ok {
		t.Fatalf("first line of %s does not decode", path)
	}
	return e.Extra
}

// A log already past the size cap must rotate once per write instead of
// recursing through the rotation sentinels until the stack overflows.
func TestRotationPastSizeCapDoesNotRecurse(t *testing.T) {
	l, path, salt := openSmallLog(t, 1, 3)
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		var err error
		for i := 0; i < 10 && err == nil; i++ {
			err = l.Log(ctx, Event{Action: ActionRead, Outcome: OutcomeOK})
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Log: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Log did not return; rotation is recursing")
	}

	for g := 1; g <= 3; g++ {
		p := rotatedName(path, g)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("generation %d missing: %v", g, err)
		}
		report, err := VerifyChain(p, salt, nil)
		if err != nil || report.FirstBadLine != 0 {
			t.Fatalf("generation %d chain: err=%v report=%+v", g, err, report)
		}
	}
	if _, err := os.Stat(rotatedName(path, 4)); !os.IsNotExist(err) {
		t.Fatalf("generation beyond retention kept: %v", err)
	}
	if report, err := VerifyChain(path, salt, nil); err != nil || report.FirstBadLine != 0 {
		t.Fatalf("live log chain: err=%v report=%+v", err, report)
	}
}

func TestRotationShiftsGenerationsAndLinksFiles(t *testing.T) {
	l, path, salt := openSmallLog(t, 1<<20, 5)
	ctx := context.Background()
	key := DeriveChainMACKey(salt)

	for i := 0; i < 3; i++ {
		if err := l.Log(ctx, Event{Action: ActionWrite, Outcome: OutcomeOK}); err != nil {
			t.Fatal(err)
		}
		if err := l.Rotate(); err != nil {
			t.Fatalf("Rotate %d: %v", i, err)
		}
	}

	// Each file's first line names the HMAC of the previous generation's
	// last line: live → .1 → .2 → .3.
	chain := []string{path, rotatedName(path, 1), rotatedName(path, 2), rotatedName(path, 3)}
	for i := 0; i < len(chain)-1; i++ {
		newer, older := chain[i], chain[i+1]
		extra := firstEventExtra(t, newer, l.auditDEK)
		got, _ := extra["prev_file_hmac"].(string)
		want := audithmac.Of(key, []byte(lastLine(t, older)))
		if got == "" || got != want {
			t.Fatalf("%s does not link to %s: prev_file_hmac=%q want %q", filepath.Base(newer), filepath.Base(older), got, want)
		}
	}
	if _, err := os.Stat(rotatedName(path, 4)); !os.IsNotExist(err) {
		t.Fatalf("unexpected generation 4: %v", err)
	}
}

func TestRotateAfterCloseFails(t *testing.T) {
	l, path, _ := openSmallLog(t, 1<<20, 2)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Rotate(); err != ErrLogClosed {
		t.Fatalf("Rotate after Close = %v, want ErrLogClosed", err)
	}
	if err := l.Log(context.Background(), Event{Action: ActionRead}); err != ErrLogClosed {
		t.Fatalf("Log after Close = %v, want ErrLogClosed", err)
	}
	if _, err := os.Stat(rotatedName(path, 1)); !os.IsNotExist(err) {
		t.Fatalf("closed logger rotated its file: %v", err)
	}
}
