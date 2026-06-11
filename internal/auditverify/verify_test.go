// Package auditverify_test provides comprehensive tests for the HMAC-chain
// verifier. The tests are hermetic (no network, no OS keychain).
package auditverify_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	audithmac "github.com/keylatch/keylatch/internal/audit/hmac"
	"github.com/keylatch/keylatch/internal/auditverify"
)

// testSalt returns a deterministic 32-byte salt for tests.
func testSalt(seed byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = seed + byte(i)
	}
	return s
}

// testDEK returns a deterministic 32-byte DEK for tests.
func testDEK(seed byte) []byte {
	d := make([]byte, 32)
	for i := range d {
		d[i] = seed + byte(i)
	}
	return d
}

// auditDir creates a 0700 parent directory and returns the log path.
func auditDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	logDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return filepath.Join(logDir, "audit.log")
}

// buildLog writes n events to a fresh audit log at path using the given salt
// and DEK, closes it, then returns the raw bytes.
func buildLog(t *testing.T, path string, salt, dek []byte, n int) []byte {
	t.Helper()
	l, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if err := l.Log(ctx, audit.Event{
			Action:  audit.ActionRead,
			Outcome: audit.OutcomeOK,
			Path:    "default/key",
		}); err != nil {
			t.Fatalf("Log[%d]: %v", i, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return data
}

// TestVerify_ValidChain tests a valid chain with several entries.
func TestVerify_ValidChain(t *testing.T) {
	salt := testSalt(1)
	dek := testDEK(101)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 5)

	if err := auditverify.Verify(raw, salt); err != nil {
		t.Errorf("Verify valid chain: got %v, want nil", err)
	}
}

// TestVerify_EmptyLog tests that an empty log is considered valid.
func TestVerify_EmptyLog(t *testing.T) {
	salt := testSalt(2)
	if err := auditverify.Verify([]byte{}, salt); err != nil {
		t.Errorf("Verify empty log: got %v, want nil", err)
	}
}

// TestVerify_BlankLinesOnly tests that a file of blank lines passes (treated as empty).
func TestVerify_BlankLinesOnly(t *testing.T) {
	salt := testSalt(3)
	if err := auditverify.Verify([]byte("\n\n\n"), salt); err != nil {
		t.Errorf("Verify blank-lines-only: got %v, want nil", err)
	}
}

// TestVerify_TamperedEntry tests that mutating a sealed body is detected.
func TestVerify_TamperedEntry(t *testing.T) {
	salt := testSalt(4)
	dek := testDEK(104)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 3)

	// Flip a byte in the middle of the log to corrupt an entry.
	mid := len(raw) / 2
	corrupted := make([]byte, len(raw))
	copy(corrupted, raw)
	corrupted[mid] ^= 0xFF

	// The tampering either changes the HMAC link or corrupts the header.
	// Either way, Verify must not return nil.
	err := auditverify.Verify(corrupted, salt)
	if err == nil {
		t.Error("Verify corrupted entry: got nil, want error")
	}
}

// TestVerify_TamperedHeader tests that altering the base64-encoded header is detected.
func TestVerify_TamperedHeader(t *testing.T) {
	salt := testSalt(5)
	dek := testDEK(105)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 2)

	// Replace the first line entirely with gibberish to break the chain.
	lines := strings.Split(string(raw), "\n")
	if len(lines) < 2 {
		t.Skip("not enough lines to tamper")
	}
	// Tamper: replace line[0] with just "garbage body" (no space separator).
	lines[0] = "notbase64notvalid"
	tampered := []byte(strings.Join(lines, "\n"))

	err := auditverify.Verify(tampered, salt)
	if err == nil {
		t.Error("Verify tampered header: got nil, want error")
	}
}

// TestVerify_BrokenChainLink tests that an HMAC mismatch between two consecutive
// entries is detected.
func TestVerify_BrokenChainLink(t *testing.T) {
	salt := testSalt(6)
	dek := testDEK(106)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 3)

	// Swap lines 1 and 2 to break the chain link.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("need at least 3 lines, got %d", len(lines))
	}
	lines[0], lines[1] = lines[1], lines[0]
	swapped := []byte(strings.Join(lines, "\n") + "\n")

	err := auditverify.Verify(swapped, salt)
	if err == nil {
		t.Error("Verify swapped lines: got nil, want error")
	}
}

// TestVerify_DeletedEntry tests that a missing entry (sequence gap) is detected.
func TestVerify_DeletedEntry(t *testing.T) {
	salt := testSalt(7)
	dek := testDEK(107)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 4)

	// Remove one line from the middle to create a sequence gap.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("need at least 3 lines, got %d", len(lines))
	}
	// Delete line at index 1 (seq=2).
	deleted := append(lines[:1], lines[2:]...)
	withGap := []byte(strings.Join(deleted, "\n") + "\n")

	err := auditverify.Verify(withGap, salt)
	if err == nil {
		t.Error("Verify deleted entry: got nil, want error")
	}
}

// TestVerify_TruncatedFile tests that a file cut mid-line is detected as truncated.
func TestVerify_TruncatedFile(t *testing.T) {
	salt := testSalt(8)
	dek := testDEK(108)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 3)

	// Find the last newline and remove everything after the second-to-last one,
	// stopping halfway through the final line to guarantee a mid-line cut.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("need at least 2 lines, got %d", len(lines))
	}

	// Take all complete lines except the last, then append half of the last line.
	// This guarantees the final "line" has no space separator.
	lastLine := lines[len(lines)-1]
	cut := lastLine[:len(lastLine)/3] // keep only the first third (part of the base64 header)
	truncated := strings.Join(lines[:len(lines)-1], "\n") + "\n" + cut + "\n"

	err := auditverify.Verify([]byte(truncated), salt)
	if err == nil {
		t.Error("Verify truncated file: got nil, want error")
	}
}

// TestVerify_MalformedJSONLines tests a line with valid base64 but invalid JSON in the header.
func TestVerify_MalformedJSONLines(t *testing.T) {
	salt := testSalt(9)

	// Build a line with valid base64 that decodes to invalid JSON.
	badJSON := base64.StdEncoding.EncodeToString([]byte("{not json"))
	badBody := base64.StdEncoding.EncodeToString([]byte("body"))
	line := badJSON + " " + badBody + "\n"

	err := auditverify.Verify([]byte(line), salt)
	if err == nil {
		t.Error("Verify malformed JSON header: got nil, want error")
	}
}

// TestVerify_WrongHMACKey tests that verifying a valid chain with the wrong key fails.
func TestVerify_WrongHMACKey(t *testing.T) {
	salt := testSalt(10)
	dek := testDEK(110)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 3)

	wrongSalt := testSalt(200) // different seed → different key
	err := auditverify.Verify(raw, wrongSalt)
	if err == nil {
		t.Error("Verify with wrong HMAC key: got nil, want error")
	}
}

// TestVerify_ReorderedLines tests that duplicate/decremented sequence numbers are detected.
func TestVerify_ReorderedLines(t *testing.T) {
	salt := testSalt(11)
	dek := testDEK(111)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 3)

	// Duplicate the first line so seq 1 appears twice (seq decrease on second occurrence).
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("need at least 2 lines, got %d", len(lines))
	}
	// Insert line[0] again after line[0]: seq 1, 1, 2, 3 → reorder error on second seq=1.
	reordered := append([]string{lines[0], lines[0]}, lines[1:]...)
	reorderedBytes := []byte(strings.Join(reordered, "\n") + "\n")

	err := auditverify.Verify(reorderedBytes, salt)
	if err == nil {
		t.Error("Verify reordered lines: got nil, want error")
	}
}

// TestVerify_LineWithNoSpace tests a line that has no space (malformed, no header/body split).
func TestVerify_LineWithNoSpace(t *testing.T) {
	salt := testSalt(12)
	line := "validbase64butnoseparator\n"

	err := auditverify.Verify([]byte(line), salt)
	if err == nil {
		t.Error("Verify no-space line: got nil, want error")
	}
}

// TestVerify_InvalidBase64Header tests a line where the header is not valid base64.
func TestVerify_InvalidBase64Header(t *testing.T) {
	salt := testSalt(13)
	// "!!!" is not valid base64.
	line := "!!! validbody\n"

	err := auditverify.Verify([]byte(line), salt)
	if err == nil {
		t.Error("Verify invalid base64 header: got nil, want error")
	}
}

// TestVerify_FirstLineSeqNotOne tests a log whose first entry has seq != 1.
func TestVerify_FirstLineSeqNotOne(t *testing.T) {
	salt := testSalt(14)
	chainMACKey := audit.DeriveChainMACKey(salt)

	// Build a header with seq=2 (wrong for first entry).
	type fakeHdr struct {
		Seq      int64  `json:"seq"`
		PrevHMAC string `json:"prev_hmac"`
		TSUnix   int64  `json:"ts_unix"`
	}
	hdr := fakeHdr{
		Seq:      2, // wrong — first entry must be seq=1
		PrevHMAC: strings.Repeat("0", 32),
		TSUnix:   1000000,
	}
	hdrBytes, _ := json.Marshal(hdr)
	hdrB64 := base64.StdEncoding.EncodeToString(hdrBytes)
	bodyB64 := base64.StdEncoding.EncodeToString([]byte("fakebody"))

	line := hdrB64 + " " + bodyB64 + "\n"
	_ = chainMACKey // used implicitly via Verify

	err := auditverify.Verify([]byte(line), salt)
	if err == nil {
		t.Error("Verify first-line seq=2: got nil, want error")
	}
}

// TestVerify_FirstLinePrevHMACNotZeros tests a log whose first entry has non-zero prev_hmac.
func TestVerify_FirstLinePrevHMACNotZeros(t *testing.T) {
	salt := testSalt(15)

	type fakeHdr struct {
		Seq      int64  `json:"seq"`
		PrevHMAC string `json:"prev_hmac"`
		TSUnix   int64  `json:"ts_unix"`
	}
	hdr := fakeHdr{
		Seq:      1,
		PrevHMAC: strings.Repeat("a", 32), // must be 32 zeros
		TSUnix:   1000000,
	}
	hdrBytes, _ := json.Marshal(hdr)
	hdrB64 := base64.StdEncoding.EncodeToString(hdrBytes)
	bodyB64 := base64.StdEncoding.EncodeToString([]byte("fakebody"))
	line := hdrB64 + " " + bodyB64 + "\n"

	err := auditverify.Verify([]byte(line), salt)
	if err == nil {
		t.Error("Verify first-line prev_hmac not zeros: got nil, want error")
	}
}

// TestVerify_SentinelErrors tests that the error sentinels are distinct and exported.
func TestVerify_SentinelErrors(t *testing.T) {
	errs := []error{
		auditverify.ErrChainDeleted,
		auditverify.ErrChainTruncated,
		auditverify.ErrChainReordered,
		auditverify.ErrChainCorrupted,
	}
	seen := make(map[string]bool)
	for _, e := range errs {
		s := e.Error()
		if seen[s] {
			t.Errorf("duplicate sentinel error message: %q", s)
		}
		seen[s] = true
		if s == "" {
			t.Errorf("sentinel error has empty message")
		}
	}
}

// TestVerify_SingleValidEntry tests a single-entry chain (minimum viable log).
func TestVerify_SingleValidEntry(t *testing.T) {
	salt := testSalt(16)
	dek := testDEK(116)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 1)

	if err := auditverify.Verify(raw, salt); err != nil {
		t.Errorf("Verify single-entry chain: got %v, want nil", err)
	}
}

// TestVerify_ChainAfterReopen tests that a chain written in two sessions verifies correctly.
func TestVerify_ChainAfterReopen(t *testing.T) {
	salt := testSalt(17)
	dek := testDEK(117)
	path := auditDir(t)

	// First session: write 3 entries.
	buildLog(t, path, salt, dek, 3)

	// Second session: append 2 more entries.
	l, err := audit.Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open (second session): %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := l.Log(ctx, audit.Event{
			Action:  audit.ActionWrite,
			Outcome: audit.OutcomeOK,
		}); err != nil {
			t.Fatalf("Log[%d]: %v", i, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if err := auditverify.Verify(raw, salt); err != nil {
		t.Errorf("Verify chain after reopen: got %v, want nil", err)
	}
}

// TestVerify_HMACLinkMismatch tests that replacing one entry's prev_hmac with the
// wrong value triggers ErrChainCorrupted.
func TestVerify_HMACLinkMismatch(t *testing.T) {
	salt := testSalt(18)
	dek := testDEK(118)
	path := auditDir(t)

	raw := buildLog(t, path, salt, dek, 2)

	// Parse line 2 and replace its prev_hmac with garbage, re-encode.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("need at least 2 lines, got %d", len(lines))
	}

	// Decode header of line[1], modify prev_hmac, re-encode.
	parts := strings.SplitN(lines[1], " ", 2)
	if len(parts) != 2 {
		t.Fatal("malformed second line")
	}
	hdrBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}

	type rawHdr struct {
		Seq      int64  `json:"seq"`
		PrevHMAC string `json:"prev_hmac"`
		TSUnix   int64  `json:"ts_unix"`
	}
	var hdr rawHdr
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	hdr.PrevHMAC = strings.Repeat("f", 32) // wrong HMAC
	newHdrBytes, _ := json.Marshal(hdr)
	lines[1] = base64.StdEncoding.EncodeToString(newHdrBytes) + " " + parts[1]

	tampered := []byte(strings.Join(lines, "\n") + "\n")

	err = auditverify.Verify(tampered, salt)
	if err == nil {
		t.Error("Verify HMAC link mismatch: got nil, want ErrChainCorrupted")
	}
}

// TestVerify_DeriveChainMACKey verifies the exported helper works correctly.
func TestVerify_DeriveChainMACKey(t *testing.T) {
	salt := testSalt(19)
	key := audit.DeriveChainMACKey(salt)
	if len(key) != 32 {
		t.Errorf("DeriveChainMACKey: got %d bytes, want 32", len(key))
	}

	// Same salt → same key (deterministic).
	key2 := audit.DeriveChainMACKey(salt)
	if string(key) != string(key2) {
		t.Error("DeriveChainMACKey not deterministic")
	}

	// Different salt → different key.
	key3 := audit.DeriveChainMACKey(testSalt(99))
	if string(key) == string(key3) {
		t.Error("DeriveChainMACKey: different salts produced same key")
	}

	// Smoke-test that audithmac.Of runs without panic.
	h := audithmac.Of(key, []byte("test"))
	if len(h) != 32 {
		t.Errorf("audithmac.Of: got %d chars, want 32", len(h))
	}
}
