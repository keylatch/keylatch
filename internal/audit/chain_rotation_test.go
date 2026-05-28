package audit_test

// T-13-07: audit log rotation cross-file chain continuity test.
//
// Verifies that:
//  1. The old file ends with a "rotation" sentinel event (ActionAuditRotate).
//  2. The new file starts with a "rotation-continued" sentinel event (ActionAuditRotate).
//  3. Both files pass VerifyChain independently (chain is valid in each file).
//  4. The prev_file_hmac stored in the new file's first Extra equals the HMAC
//     of the last raw line of the old file, computed with the chain MAC key
//     derived from the audit salt — linking the two files.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	audithmac "github.com/keylatch/keylatch/internal/audit/hmac"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// TestAuditChainContinuityAcrossRotation writes events, rotates, then asserts
// cross-file chain linkage and independent chain validity.
func TestAuditChainContinuityAcrossRotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := auditLogPath(t, dir)

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 7)
	}
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 77)
	}

	l, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	ctx := context.Background()

	// Write 3 events before rotation.
	for i := 0; i < 3; i++ {
		if err := l.Log(ctx, audit.Event{
			Action:  audit.ActionRead,
			Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatalf("Log[%d]: %v", i, err)
		}
	}

	// Rotate.
	if err := l.Rotate(); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Write 2 more events to the new file.
	for i := 0; i < 2; i++ {
		if err := l.Log(ctx, audit.Event{
			Action:  audit.ActionWrite,
			Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatalf("Log post-rotate[%d]: %v", i, err)
		}
	}

	rotatedPath := path + ".1"

	// Both files must exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("new log file missing: %v", err)
	}
	if _, err := os.Stat(rotatedPath); err != nil {
		t.Fatalf("old (rotated) log file missing: %v", err)
	}

	// Both files must pass VerifyChain.
	oldReport, err := audit.VerifyChain(rotatedPath, salt, dek)
	if err != nil {
		t.Fatalf("VerifyChain(old): %v", err)
	}
	if oldReport.FirstBadLine != 0 {
		t.Errorf("VerifyChain(old): first bad line %d — %s", oldReport.FirstBadLine, oldReport.FirstBadReason)
	}
	if oldReport.TotalLines < 4 {
		// 3 events + 1 rotation sentinel = 4 lines minimum.
		t.Errorf("VerifyChain(old): expected ≥4 lines, got %d", oldReport.TotalLines)
	}

	newReport, err := audit.VerifyChain(path, salt, dek)
	if err != nil {
		t.Fatalf("VerifyChain(new): %v", err)
	}
	if newReport.FirstBadLine != 0 {
		t.Errorf("VerifyChain(new): first bad line %d — %s", newReport.FirstBadLine, newReport.FirstBadReason)
	}
	if newReport.TotalLines < 3 {
		// 1 rotation-continued sentinel + 2 post-rotate events = 3 lines minimum.
		t.Errorf("VerifyChain(new): expected ≥3 lines, got %d", newReport.TotalLines)
	}

	// Cross-file chain continuity: the HMAC of the last raw line of the old file
	// must equal prev_file_hmac in the first event of the new file.
	chainMACKey := audit.DeriveChainMACKey(salt)

	// Read the last raw line of the old file (without trailing newline).
	lastRawLine := readLastRawLine(t, rotatedPath)
	expectedPrevFileHMAC := audithmac.Of(chainMACKey, []byte(lastRawLine))

	// Read the first decrypted event from the new file and check its prev_file_hmac.
	newFirstExtra := readFirstDecryptedExtra(t, path, dek)

	prevFileHMAC, ok := newFirstExtra["prev_file_hmac"].(string)
	if !ok || prevFileHMAC == "" {
		t.Errorf("new file first event missing 'prev_file_hmac' in Extra: %v", newFirstExtra)
		return
	}

	if prevFileHMAC != expectedPrevFileHMAC {
		t.Errorf("cross-file HMAC mismatch:\n  computed from old last line = %s\n  new prev_file_hmac         = %s",
			expectedPrevFileHMAC, prevFileHMAC)
	}
}

// readLastRawLine returns the last non-empty line of the file, without trailing newline.
func readLastRawLine(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] != "" {
			return lines[i]
		}
	}
	t.Fatalf("no lines in %s", path)
	return ""
}

// auditEventRaw holds just the Extra field for cross-file chain checks.
type auditEventRaw struct {
	Action  string                 `json:"action"`
	Outcome string                 `json:"outcome"`
	Extra   map[string]interface{} `json:"extra,omitempty"`
}

// readFirstDecryptedExtra opens a log file and returns the Extra map of the first decryptable event.
func readFirstDecryptedExtra(t *testing.T, path string, dek []byte) map[string]interface{} {
	t.Helper()
	events := decryptAllEvents(t, path, dek)
	if len(events) == 0 {
		t.Fatalf("no events in %s", path)
	}
	first := events[0]
	if first.Extra == nil {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{})
	for k, v := range first.Extra {
		out[k] = v
	}
	return out
}

// decryptAllEvents reads and decrypts all events from an audit log file.
func decryptAllEvents(t *testing.T, path string, dek []byte) []auditEventRaw {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var events []auditEventRaw
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		hdrBytes, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			continue
		}
		sealed, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil || len(sealed) < 24 {
			continue
		}
		nonce := sealed[:24]
		ct := sealed[24:]

		plaintext, err := envelope.Open(envelope.XChaCha20Poly1305, dek, ct, nonce, hdrBytes)
		if err != nil {
			continue
		}
		var e auditEventRaw
		if err := json.Unmarshal(plaintext, &e); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events
}
