package audit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
)

// FuzzAuditLineParser verifies that the audit log parser never panics and
// never nil-pointer-dereferences on arbitrary byte inputs written as raw
// log content. The parser is exercised via Open (which seeds chain state
// from the last line) and Summarize (which iterates all lines).
func FuzzAuditLineParser(f *testing.F) {
	// Seed corpus.
	validLine := "eyJzZXEiOjEsInByZXZfaG1hYyI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidHNfdW5peCI6MTc0NzE3NjAwMDAwMDAwMDAwfQ== dGVzdA==\n"
	seeds := [][]byte{
		{},           // empty
		[]byte("\n"), // blank line
		[]byte("notbase64 notbase64\n"),
		[]byte(validLine),
		[]byte("abc\n"),
		[]byte("abc def ghi\n"), // three space-separated parts
		{0x00, 0x01, 0x02},      // random bytes
		[]byte(`{"seq":1} `),    // truncated JSON base64
	}
	for _, s := range seeds {
		f.Add(s)
	}

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 100)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Write fuzzed data as the raw log file content.
		dir := t.TempDir()
		auditDir := filepath.Join(dir, "auditlogs")
		if err := os.MkdirAll(auditDir, 0o700); err != nil {
			return
		}
		logPath := filepath.Join(auditDir, "audit.log")
		// Write raw fuzzed bytes — these may not be valid audit lines.
		if err := os.WriteFile(logPath, data, 0o600); err != nil {
			return
		}

		// Open must not panic. It may return an error for corrupt input.
		l, err := audit.Open(logPath, salt, dek)
		if err != nil {
			// Error is acceptable for arbitrary input; panic is not.
			return
		}
		defer l.Close()

		// Summarize must not panic or nil-deref on arbitrary content.
		_, _ = l.Summarize(audit.SummaryOpts{})
	})
}
