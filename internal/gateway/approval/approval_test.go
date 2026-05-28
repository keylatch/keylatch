// Package approval tests cover the security-critical approval flow for
// gateway actions. The flow is: RequestNew → Pending → (Approve|Deny) →
// Verify. Each step has invariants that, if violated, would let an
// agent escalate without explicit human approval. The tests below
// exercise every exported function plus the helpers reached only via
// edge cases (corrupt files, expired entries, malformed JSON, etc.) to
// keep coverage on this package at or above 80%.
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// withDir creates a fresh approvals directory for a single test.
func withDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// makeRequest creates a pending approval with a default TTL.
func makeRequest(t *testing.T, dir string) *ApprovalRequest {
	t.Helper()
	ar, err := RequestNew(context.Background(), dir, "actor-1", "openai.chat", "conn-1", "req-hash-abc", time.Hour)
	if err != nil {
		t.Fatalf("RequestNew: %v", err)
	}
	return ar
}

// --------------------------- RequestNew ---------------------------

func TestRequestNew_PersistsFileWithMode0600(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)

	if !strings.HasPrefix(ar.Token, "apv_") {
		t.Errorf("token should be prefixed with 'apv_'; got %q", ar.Token)
	}
	if ar.Status != StatusPending {
		t.Errorf("new request must be pending; got %q", ar.Status)
	}
	if ar.CreatedAt.IsZero() || ar.ExpiresAt.IsZero() {
		t.Errorf("timestamps must be set; got created=%v expires=%v", ar.CreatedAt, ar.ExpiresAt)
	}
	if !ar.ExpiresAt.After(ar.CreatedAt) {
		t.Errorf("expires_at must be after created_at; got created=%v expires=%v", ar.CreatedAt, ar.ExpiresAt)
	}

	// File exists with mode 0600.
	path := filepath.Join(dir, ar.Token+".json")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	assertPOSIXMode(t, st, 0o600, "approval file")
}

func TestRequestNew_ZeroTTL_DefaultsTo15Minutes(t *testing.T) {
	dir := withDir(t)
	ar, err := RequestNew(context.Background(), dir, "a", "c", "n", "h", 0)
	if err != nil {
		t.Fatalf("RequestNew: %v", err)
	}
	delta := ar.ExpiresAt.Sub(ar.CreatedAt)
	// Allow a few seconds of skew for slow CI.
	if delta < 14*time.Minute || delta > 16*time.Minute {
		t.Errorf("zero TTL should default to 15m; got %v", delta)
	}
}

func TestRequestNew_NegativeTTL_DefaultsTo15Minutes(t *testing.T) {
	dir := withDir(t)
	ar, err := RequestNew(context.Background(), dir, "a", "c", "n", "h", -time.Hour)
	if err != nil {
		t.Fatalf("RequestNew: %v", err)
	}
	delta := ar.ExpiresAt.Sub(ar.CreatedAt)
	if delta < 14*time.Minute || delta > 16*time.Minute {
		t.Errorf("negative TTL should default to 15m; got %v", delta)
	}
}

func TestRequestNew_CreatesDirectoryWithMode0700(t *testing.T) {
	dir := filepath.Join(withDir(t), "approvals-nested")
	ar, err := RequestNew(context.Background(), dir, "a", "c", "n", "h", time.Hour)
	if err != nil {
		t.Fatalf("RequestNew: %v", err)
	}
	if ar == nil {
		t.Fatal("request must not be nil")
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("dir stat: %v", err)
	}
	if !st.IsDir() {
		t.Fatal("approvals path must be a directory")
	}
	assertPOSIXMode(t, st, 0o700, "approvals dir")
}

func TestRequestNew_RejectsUnwritableDirectory(t *testing.T) {
	// Use a parent path that is read-only. On most Unix CI runners /proc
	// is read-only and a child mkdir under it fails with EROFS or EACCES.
	if runtime.GOOS == "windows" {
		t.Skip("/proc does not exist on Windows; read-only-fs test is Unix-only")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root — read-only-fs errors do not occur")
	}
	dir := "/proc/1/no_such_dir/keylatch_test"
	_, err := RequestNew(context.Background(), dir, "a", "c", "n", "h", time.Hour)
	if err == nil {
		t.Fatal("expected error when writing under a non-writable parent")
	}
	if !strings.Contains(err.Error(), "approval: mkdir") {
		t.Errorf("expected mkdir error; got %v", err)
	}
}

func TestRequestNew_TokenIsUniquePerCall(t *testing.T) {
	dir := withDir(t)
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		ar := makeRequest(t, dir)
		if seen[ar.Token] {
			t.Fatalf("duplicate token generated: %s", ar.Token)
		}
		seen[ar.Token] = true
	}
}

// --------------------------- Pending ---------------------------

func TestPending_EmptyDirectory(t *testing.T) {
	dir := withDir(t)
	got, err := Pending(context.Background(), dir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty directory must return no entries; got %d", len(got))
	}
}

func TestPending_NonExistentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	got, err := Pending(context.Background(), dir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("non-existent dir must return empty list; got %d", len(got))
	}
}

func TestPending_ReturnsOnlyPending(t *testing.T) {
	dir := withDir(t)
	pendingAR := makeRequest(t, dir)
	approvedAR := makeRequest(t, dir)
	deniedAR := makeRequest(t, dir)

	if err := Approve(context.Background(), dir, approvedAR.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := Deny(context.Background(), dir, deniedAR.Token); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	got, err := Pending(context.Background(), dir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one pending entry; got %d", len(got))
	}
	if got[0].Token != pendingAR.Token {
		t.Errorf("expected pending token %q; got %q", pendingAR.Token, got[0].Token)
	}
}

func TestPending_SkipsExpired(t *testing.T) {
	dir := withDir(t)

	// Create one expired entry by writing it directly.
	expiredToken := "apv_expired"
	expired := &ApprovalRequest{
		Token:     expiredToken,
		Actor:     "a",
		Status:    StatusPending,
		CreatedAt: time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := writeApproval(filepath.Join(dir, expiredToken+".json"), expired); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}

	// Create one fresh entry.
	freshAR := makeRequest(t, dir)

	got, err := Pending(context.Background(), dir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one non-expired pending; got %d", len(got))
	}
	if got[0].Token != freshAR.Token {
		t.Errorf("expected fresh token %q; got %q", freshAR.Token, got[0].Token)
	}
}

func TestPending_IgnoresNonJSONFiles(t *testing.T) {
	dir := withDir(t)
	makeRequest(t, dir)

	// Drop a non-JSON sibling file. Pending should skip it silently.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}

	got, err := Pending(context.Background(), dir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("non-JSON file must be ignored; got %d entries", len(got))
	}
}

func TestPending_IgnoresCorruptJSON(t *testing.T) {
	dir := withDir(t)
	makeRequest(t, dir)

	// Drop a corrupt JSON file. readApproval returns an error; Pending
	// must skip the entry rather than abort.
	if err := os.WriteFile(filepath.Join(dir, "apv_corrupt.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}

	got, err := Pending(context.Background(), dir)
	if err != nil {
		t.Fatalf("Pending must not error on corrupt entries: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("corrupt entry must be skipped; got %d entries", len(got))
	}
}

func TestPending_FailsOnUnreadableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod 0o000 does not restrict directory access on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read unreadable dirs")
	}
	dir := withDir(t)
	makeRequest(t, dir)
	// Remove read bit.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, err := Pending(context.Background(), dir)
	if err == nil {
		t.Fatal("expected readdir error on unreadable directory")
	}
	if !strings.Contains(err.Error(), "approval: readdir") {
		t.Errorf("expected readdir error wrapper; got %v", err)
	}
}

// --------------------------- Approve / Deny ---------------------------

func TestApprove_TransitionsPendingToApproved(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)

	if err := Approve(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got, err := readApproval(filepath.Join(dir, ar.Token+".json"))
	if err != nil {
		t.Fatalf("readApproval: %v", err)
	}
	if got.Status != StatusApproved {
		t.Errorf("status must be approved; got %q", got.Status)
	}
}

func TestApprove_NotFoundReturnsErrNotFound(t *testing.T) {
	dir := withDir(t)
	err := Approve(context.Background(), dir, "apv_does_not_exist")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound; got %v", err)
	}
}

func TestApprove_AlreadyApprovedReturnsErrAlreadyActed(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)

	if err := Approve(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("first Approve: %v", err)
	}
	if err := Approve(context.Background(), dir, ar.Token); err != ErrAlreadyActed {
		t.Errorf("second Approve must return ErrAlreadyActed; got %v", err)
	}
}

func TestApprove_DeniedThenApproveReturnsErrAlreadyActed(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)

	if err := Deny(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if err := Approve(context.Background(), dir, ar.Token); err != ErrAlreadyActed {
		t.Errorf("Approve after Deny must return ErrAlreadyActed; got %v", err)
	}
}

func TestDeny_TransitionsPendingToDenied(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)

	if err := Deny(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	got, err := readApproval(filepath.Join(dir, ar.Token+".json"))
	if err != nil {
		t.Fatalf("readApproval: %v", err)
	}
	if got.Status != StatusDenied {
		t.Errorf("status must be denied; got %q", got.Status)
	}
}

func TestDeny_NotFoundReturnsErrNotFound(t *testing.T) {
	dir := withDir(t)
	err := Deny(context.Background(), dir, "apv_nope")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound; got %v", err)
	}
}

// --------------------------- Verify ---------------------------

func TestVerify_HappyPath(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash); err != nil {
		t.Errorf("Verify should succeed; got %v", err)
	}
}

func TestVerify_EmptyRequestHashSkipsHashCheck(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := Verify(context.Background(), dir, ar.Token, ""); err != nil {
		t.Errorf("Verify with empty hash should succeed; got %v", err)
	}
}

func TestVerify_NotFoundReturnsErrNotFound(t *testing.T) {
	dir := withDir(t)
	err := Verify(context.Background(), dir, "apv_does_not_exist", "h")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound; got %v", err)
	}
}

func TestVerify_PendingStatusRejected(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)
	err := Verify(context.Background(), dir, ar.Token, ar.RequestHash)
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Errorf("Verify must reject pending status; got %v", err)
	}
}

func TestVerify_DeniedStatusRejected(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)
	if err := Deny(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	err := Verify(context.Background(), dir, ar.Token, ar.RequestHash)
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Errorf("Verify must reject denied status; got %v", err)
	}
}

func TestVerify_ExpiredReturnsErrExpired(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// Backdate the expiry directly.
	path := filepath.Join(dir, ar.Token+".json")
	got, err := readApproval(path)
	if err != nil {
		t.Fatalf("readApproval: %v", err)
	}
	got.ExpiresAt = time.Now().Add(-time.Minute)
	if err := writeApproval(path, got); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}

	err = Verify(context.Background(), dir, ar.Token, ar.RequestHash)
	if err != ErrExpired {
		t.Errorf("expected ErrExpired; got %v", err)
	}
}

func TestVerify_RequestHashMismatchRejected(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	err := Verify(context.Background(), dir, ar.Token, "different-hash")
	if err == nil || !strings.Contains(err.Error(), "request hash mismatch") {
		t.Errorf("Verify must reject hash mismatch; got %v", err)
	}
}

// --------------------------- internal helpers ---------------------------

func TestNewApprovalToken_FormatAndLength(t *testing.T) {
	for i := 0; i < 20; i++ {
		tok, err := newApprovalToken()
		if err != nil {
			t.Fatalf("newApprovalToken: %v", err)
		}
		if !strings.HasPrefix(tok, "apv_") {
			t.Errorf("token must start with apv_; got %q", tok)
		}
		// apv_ + 32 hex chars = 36 total
		if len(tok) != 36 {
			t.Errorf("token must be 36 chars (apv_ + 32 hex); got %d (%q)", len(tok), tok)
		}
	}
}

func TestReadApproval_NonExistentReturnsErrNotFound(t *testing.T) {
	_, err := readApproval(filepath.Join(t.TempDir(), "missing.json"))
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound; got %v", err)
	}
}

func TestReadApproval_CorruptJSONReturnsParseError(t *testing.T) {
	dir := withDir(t)
	path := filepath.Join(dir, "apv_bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := readApproval(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "approval: parse") {
		t.Errorf("expected parse error; got %v", err)
	}
}

func TestReadApproval_UnreadableFileReturnsReadError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.WriteFile 0o000 does not restrict file read access on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read unreadable files")
	}
	dir := withDir(t)
	path := filepath.Join(dir, "apv_unreadable.json")
	if err := os.WriteFile(path, []byte("{}"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := readApproval(path)
	if err == nil {
		t.Fatal("expected read error")
	}
	if !strings.Contains(err.Error(), "approval: read") && err != ErrNotFound {
		t.Errorf("expected approval: read wrap; got %v", err)
	}
}

func TestWriteApproval_AtomicRename(t *testing.T) {
	// After write, the .tmp file must not be visible.
	dir := withDir(t)
	ar := &ApprovalRequest{
		Token:     "apv_test_atomic",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	path := filepath.Join(dir, ar.Token+".json")
	if err := writeApproval(path, ar); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}
	tmpPath := path + ".tmp"
	_, err := os.Stat(tmpPath)
	if !os.IsNotExist(err) {
		t.Errorf("temp file must be cleaned up after rename; stat err=%v", err)
	}
	// Final file must be 0600.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	assertPOSIXMode(t, st, 0o600, "final file")
}

func TestWriteApproval_RoundTripPreservesAllFields(t *testing.T) {
	dir := withDir(t)
	original := &ApprovalRequest{
		Token:       "apv_roundtrip",
		Actor:       "actor-rt",
		Capability:  "cap-rt",
		Connection:  "conn-rt",
		RequestHash: "hash-rt",
		Status:      StatusApproved,
		ExpiresAt:   time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		Note:        "lgtm",
	}
	path := filepath.Join(dir, original.Token+".json")
	if err := writeApproval(path, original); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}
	got, err := readApproval(path)
	if err != nil {
		t.Fatalf("readApproval: %v", err)
	}

	// Compare via JSON to ignore timezone instance differences.
	wantJSON, _ := json.Marshal(original)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("round-trip mismatch:\nwant=%s\ngot =%s", wantJSON, gotJSON)
	}
}

// --------------------------- integration ---------------------------

func TestFlow_RequestApproveVerifyHappyPath(t *testing.T) {
	dir := withDir(t)

	// Request.
	ar := makeRequest(t, dir)

	// Pending sees it.
	pending, err := Pending(context.Background(), dir)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 || pending[0].Token != ar.Token {
		t.Errorf("pending should contain the new token; got %+v", pending)
	}

	// Approve.
	if err := Approve(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Pending no longer sees it.
	pending, err = Pending(context.Background(), dir)
	if err != nil {
		t.Fatalf("Pending after approve: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending must be empty after approve; got %+v", pending)
	}

	// Verify succeeds with the original hash.
	if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash); err != nil {
		t.Errorf("Verify should succeed; got %v", err)
	}

	// Verify fails on hash mismatch.
	if err := Verify(context.Background(), dir, ar.Token, "wrong"); err == nil {
		t.Error("Verify must fail on hash mismatch")
	}
}

func TestFlow_RequestDenyVerifyRejected(t *testing.T) {
	dir := withDir(t)
	ar := makeRequest(t, dir)
	if err := Deny(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash); err == nil {
		t.Error("Verify must reject denied entry")
	}
}

func assertPOSIXMode(t *testing.T, st os.FileInfo, want os.FileMode, label string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	if st.Mode().Perm() != want {
		t.Errorf("%s mode must be %o; got %o", label, want, st.Mode().Perm())
	}
}

// Ensure the file permission helper compiles against fs.FileMode — guards
// against an accidental refactor that swaps the perm bit definition.
var _ fs.FileMode = os.FileMode(0o600)

// fakeClock is a test double for Clock that returns a fixed time.
type fakeClock struct{ t time.Time }

func (f fakeClock) Now() time.Time { return f.t }

// --------------------------- List ---------------------------

func TestList_Empty(t *testing.T) {
	dir := withDir(t)
	got, err := List(context.Background(), dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty dir must return 0 entries; got %d", len(got))
	}
}

func TestList_NonExistentDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-such-dir")
	got, err := List(context.Background(), dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("non-existent dir must return 0 entries; got %d", len(got))
	}
}

func TestList_Populated(t *testing.T) {
	dir := withDir(t)
	ar1 := makeRequest(t, dir)
	ar2 := makeRequest(t, dir)

	// Approve one — approved should NOT appear in List.
	if err := Approve(context.Background(), dir, ar1.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	got, err := List(context.Background(), dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 pending entry; got %d", len(got))
	}
	if got[0].Token != ar2.Token {
		t.Errorf("expected token %q; got %q", ar2.Token, got[0].Token)
	}
}

func TestList_SortedByCreatedAtAscending(t *testing.T) {
	dir := withDir(t)

	// Write entries with explicit timestamps so order is deterministic.
	tokens := []string{"apv_a1", "apv_b2", "apv_c3"}
	for i, tok := range tokens {
		ar := &ApprovalRequest{
			Token:     tok,
			Status:    StatusPending,
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := writeApproval(filepath.Join(dir, tok+".json"), ar); err != nil {
			t.Fatalf("writeApproval: %v", err)
		}
	}

	got, err := List(context.Background(), dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries; got %d", len(got))
	}
	for i := 0; i < len(got)-1; i++ {
		if got[i].CreatedAt.After(got[i+1].CreatedAt) {
			t.Errorf("entries not sorted by CreatedAt: index %d (%v) > index %d (%v)",
				i, got[i].CreatedAt, i+1, got[i+1].CreatedAt)
		}
	}
}

func TestList_ShowsExpiredStatusForPastTTL(t *testing.T) {
	dir := withDir(t)
	// Write an expired-but-not-swept entry.
	tok := "apv_past_ttl"
	ar := &ApprovalRequest{
		Token:     tok,
		Status:    StatusPending,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute), // past TTL
	}
	if err := writeApproval(filepath.Join(dir, tok+".json"), ar); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}

	got, err := List(context.Background(), dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry; got %d", len(got))
	}
	if got[0].Status != StatusExpired {
		t.Errorf("past-TTL entry should show StatusExpired; got %q", got[0].Status)
	}
}

// --------------------------- ExpireOldPending ---------------------------

func TestStore_TTLSweep_AutoDeniesExpired(t *testing.T) {
	dir := withDir(t)

	// Create a request that is already past its TTL.
	expiredToken := "apv_sweepme"
	ar := &ApprovalRequest{
		Token:     expiredToken,
		Status:    StatusPending,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := writeApproval(filepath.Join(dir, expiredToken+".json"), ar); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}

	// Create a fresh request (should NOT be expired by sweep).
	fresh := makeRequest(t, dir)

	n, err := ExpireOldPending(context.Background(), dir)
	if err != nil {
		t.Fatalf("ExpireOldPending: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 expired entry; got %d", n)
	}

	// Verify the swept file now has StatusExpired.
	swept, err := readApproval(filepath.Join(dir, expiredToken+".json"))
	if err != nil {
		t.Fatalf("readApproval after sweep: %v", err)
	}
	if swept.Status != StatusExpired {
		t.Errorf("swept entry status = %q; want %q", swept.Status, StatusExpired)
	}

	// Fresh entry must remain pending.
	still, err := readApproval(filepath.Join(dir, fresh.Token+".json"))
	if err != nil {
		t.Fatalf("readApproval fresh: %v", err)
	}
	if still.Status != StatusPending {
		t.Errorf("fresh entry status = %q; want %q", still.Status, StatusPending)
	}
}

func TestStore_TTLSweep_NoDoubleDecide(t *testing.T) {
	dir := withDir(t)

	// Create and approve a request.
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Run sweep — should NOT change status of approved entry.
	n, err := ExpireOldPending(context.Background(), dir)
	if err != nil {
		t.Fatalf("ExpireOldPending: %v", err)
	}
	if n != 0 {
		t.Errorf("sweep must not expire already-approved entries; got n=%d", n)
	}

	got, err := readApproval(filepath.Join(dir, ar.Token+".json"))
	if err != nil {
		t.Fatalf("readApproval: %v", err)
	}
	if got.Status != StatusApproved {
		t.Errorf("approved entry must remain approved after sweep; got %q", got.Status)
	}
}

func TestStore_TTLSweep_WithFakeClock(t *testing.T) {
	dir := withDir(t)

	// Create a request with a TTL 30 seconds from now.
	ar := &ApprovalRequest{
		Token:     "apv_clocktest",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Second),
	}
	if err := writeApproval(filepath.Join(dir, ar.Token+".json"), ar); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}

	// Advance the fake clock past ExpiresAt.
	clk := fakeClock{t: ar.ExpiresAt.Add(time.Second)}

	n, err := expireOldPendingWithClock(dir, clk)
	if err != nil {
		t.Fatalf("expireOldPendingWithClock: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 expired entry with advanced clock; got %d", n)
	}
}

func TestApprove_OnExpired_ReturnsActionableError(t *testing.T) {
	dir := withDir(t)

	expiredToken := "apv_expired_approve"
	ar := &ApprovalRequest{
		Token:     expiredToken,
		Status:    StatusPending,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := writeApproval(filepath.Join(dir, expiredToken+".json"), ar); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}

	err := Approve(context.Background(), dir, expiredToken)
	if err == nil {
		t.Fatal("expected error when approving expired request")
	}

	var expErr *ErrExpiredTTL
	if !errors.As(err, &expErr) {
		t.Errorf("expected ErrExpiredTTL; got %T: %v", err, err)
	}
	if !errors.Is(err, ErrExpired) {
		t.Errorf("ErrExpiredTTL must satisfy errors.Is(ErrExpired)")
	}
}
