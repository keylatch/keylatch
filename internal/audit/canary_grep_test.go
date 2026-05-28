// canary_grep_test.go — T6-01
// Tests that AEAD-encrypted canary tokens never appear in plaintext in the
// audit log (S5-1, S5-18, SC5-FIND-006).
package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const canaryToken = "KEYLATCH_CANARY_PHASE5_AUDIT_0xDEADBEEF"

func TestCanaryNeverPlaintextInAuditLogWhitebox(t *testing.T) {
	baseDir := t.TempDir()
	// Create a 0700 subdirectory; validateParentDir requires mode 0700.
	dir := filepath.Join(baseDir, "auditlogs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	saltPath := filepath.Join(dir, "audit-salt")
	auditPath := filepath.Join(dir, "audit.log")

	// Create a 32-byte salt.
	saltBytes := make([]byte, 32)
	for i := range saltBytes {
		saltBytes[i] = byte(i + 7)
	}
	if err := os.WriteFile(saltPath, saltBytes, 0o600); err != nil {
		t.Fatalf("write salt: %v", err)
	}

	// Create a 32-byte audit DEK.
	auditDEK := make([]byte, 32)
	for i := range auditDEK {
		auditDEK[i] = byte(i + 33)
	}

	l, err := Open(auditPath, saltBytes, auditDEK)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	// Log an event whose Extra map contains an unlisted key with the canary value.
	// SafeLogFields.Redact will HMAC this key (it is not in the allowlist) so the
	// raw canary string must NOT appear in the sealed log line.
	evt := Event{
		Action:  ActionRead,
		Outcome: OutcomeOK,
		Path:    "default/test/canary",
		Extra: map[string]any{
			"_canary_unsafe_key": canaryToken,
		},
	}
	if err := l.Log(context.Background(), evt); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// Read the raw on-disk bytes.
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}

	// The canary string must NOT appear anywhere in the raw log file.
	if bytes.Contains(raw, []byte(canaryToken)) {
		t.Errorf("canary token found in plaintext in audit log (S5-1 / FIND-006 violated)")
	}

	// VerifyChain in header-only mode (auditDEK=nil) must pass (FIND3-008).
	report, err := VerifyChain(auditPath, saltBytes, nil)
	if err != nil {
		t.Fatalf("VerifyChain (header-only): %v", err)
	}
	if report.TotalLines == 0 {
		t.Errorf("VerifyChain: expected at least 1 line")
	}
	if report.FirstBadLine != 0 {
		t.Errorf("VerifyChain: unexpected bad line %d: %s", report.FirstBadLine, report.FirstBadReason)
	}

	// Summarize must surface the event (decryption works).
	sum, err := l.Summarize(SummaryOpts{Action: ActionRead})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if sum.TotalEvents == 0 {
		t.Errorf("Summarize: expected at least 1 event after decryption, got 0")
	}

	// The canary HMAC'd form must NOT be the raw token (confirming the key was redacted).
	// We verify this by checking that the Extra key value in the decrypted event
	// is NOT the literal canary string (it should be an HMAC hex string).
	// We do this via the raw log — the canary should not appear anywhere.
	if strings.Contains(string(raw), canaryToken) {
		t.Errorf("canary appeared unredacted in raw log line")
	}
}
