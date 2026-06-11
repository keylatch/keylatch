package keyring_test

// keyring_extra_test.go adds coverage for uncovered paths in the keyring package:
//   - New — XChaCha20 and AES-GCM creation
//   - NewWithSalt — valid and empty-salt error
//   - ReadHeader — delegates to loadFile; tests not-found and corrupt paths
//   - Algorithm — currently 0%
//   - keyring.Next — AES-GCM vs other algorithm
//   - RotateKEK — full path
//   - DestroyTerm — double-destroy error, not-found error
//   - NextGCMNonce — GCM-state not initialized, exhausted term counter
//   - migration.LegacyKEKTypeToRootType — all branches
//   - GCMState fields and lease-size > 0 path

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/trust"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func fastKEK(t *testing.T, passphrase string) kek.KEK {
	t.Helper()
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k, err := kek.PassphraseKEK([]byte(passphrase), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK(%q): %v", passphrase, err)
	}
	return k
}

// ---------------------------------------------------------------------------
// New — XChaCha20 and AES-GCM creation, then open
// ---------------------------------------------------------------------------

func TestNew_XChaCha20(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	k := fastKEK(t, "xchacha-new")
	if err := keyring.New(path, k, envelope.XChaCha20Poly1305, 0); err != nil {
		t.Fatalf("New: %v", err)
	}

	// File must exist and be parseable.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var kf keyring.KeyringFile
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if kf.Algorithm != envelope.XChaCha20Poly1305 {
		t.Errorf("Algorithm = %q, want %q", kf.Algorithm, envelope.XChaCha20Poly1305)
	}
	if kf.GCMState != nil {
		t.Error("GCMState should be nil for XChaCha20 keyring")
	}
}

func TestNew_AESGCM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	k := fastKEK(t, "aesgcm-new")
	if err := keyring.New(path, k, envelope.AES256GCM, 16); err != nil {
		t.Fatalf("New: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var kf keyring.KeyringFile
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if kf.Algorithm != envelope.AES256GCM {
		t.Errorf("Algorithm = %q, want %q", kf.Algorithm, envelope.AES256GCM)
	}
	if kf.GCMState == nil {
		t.Fatal("GCMState should not be nil for AES-GCM keyring")
	}
	if kf.GCMState.LeaseSize != 16 {
		t.Errorf("LeaseSize = %d, want 16", kf.GCMState.LeaseSize)
	}
}

func TestNew_CanOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	k1 := fastKEK(t, "new-open")
	if err := keyring.New(path, k1, envelope.XChaCha20Poly1305, 0); err != nil {
		t.Fatalf("New: %v", err)
	}

	k2 := fastKEK(t, "new-open")
	kr, err := keyring.Open(path, k2)
	if err != nil {
		t.Fatalf("Open after New: %v", err)
	}
	defer kr.Zero()

	dek, term, err := kr.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK: %v", err)
	}
	if term != 1 {
		t.Errorf("term = %d, want 1", term)
	}
	if len(dek) != 32 {
		t.Errorf("dek len = %d, want 32", len(dek))
	}
}

// ---------------------------------------------------------------------------
// NewWithSalt
// ---------------------------------------------------------------------------

func TestNewWithSalt_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 55)
	}

	k1 := fastKEK(t, "with-salt")
	if err := keyring.NewWithSalt(path, k1, envelope.XChaCha20Poly1305, 0, salt); err != nil {
		t.Fatalf("NewWithSalt: %v", err)
	}

	// Open and verify.
	k2 := fastKEK(t, "with-salt")
	kr, err := keyring.Open(path, k2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	_, _, err = kr.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK: %v", err)
	}
}

func TestNewWithSalt_EmptySalt_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	k := fastKEK(t, "empty-salt")
	err := keyring.NewWithSalt(path, k, envelope.XChaCha20Poly1305, 0, nil)
	if err == nil {
		t.Error("expected error for empty salt, got nil")
	}
}

func TestNewWithSalt_AESGCM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 77)
	}

	k := fastKEK(t, "aesgcm-with-salt")
	if err := keyring.NewWithSalt(path, k, envelope.AES256GCM, 8, salt); err != nil {
		t.Fatalf("NewWithSalt AES-GCM: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var kf keyring.KeyringFile
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if kf.GCMState == nil {
		t.Fatal("GCMState should not be nil")
	}
}

// ---------------------------------------------------------------------------
// ReadHeader
// ---------------------------------------------------------------------------

func TestReadHeader_Valid(t *testing.T) {
	dir := t.TempDir()
	path, _ := buildTestKeyring(t, dir, "header-test", envelope.XChaCha20Poly1305)

	kf, err := keyring.ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if kf.Algorithm != envelope.XChaCha20Poly1305 {
		t.Errorf("Algorithm = %q, want xchacha20-poly1305", kf.Algorithm)
	}
}

func TestReadHeader_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := keyring.ReadHeader(filepath.Join(dir, "nonexistent.json"))
	if !errors.Is(err, keyring.ErrKeyringNotFound) {
		t.Errorf("expected ErrKeyringNotFound, got %v", err)
	}
}

func TestReadHeader_Corrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(path, []byte("invalid-json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := keyring.ReadHeader(path)
	if !errors.Is(err, keyring.ErrKeyringCorrupt) {
		t.Errorf("expected ErrKeyringCorrupt, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Algorithm
// ---------------------------------------------------------------------------

func TestAlgorithm(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "alg-test", envelope.XChaCha20Poly1305)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	alg := kr.Algorithm()
	if alg != envelope.XChaCha20Poly1305 {
		t.Errorf("Algorithm() = %q, want xchacha20-poly1305", alg)
	}
}

func TestAlgorithm_AESGCM(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "alg-gcm", envelope.AES256GCM)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	alg := kr.Algorithm()
	if alg != envelope.AES256GCM {
		t.Errorf("Algorithm() = %q, want aes-256-gcm", alg)
	}
}

// ---------------------------------------------------------------------------
// keyring.Next — NonceProvider interface
// ---------------------------------------------------------------------------

func TestKeyringNext_AESGCM_OK(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "next-nonce", envelope.AES256GCM)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	nonce, err := kr.Next(envelope.AES256GCM, 1)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(nonce) != 12 {
		t.Errorf("nonce len = %d, want 12", len(nonce))
	}
}

func TestKeyringNext_WrongAlgorithm_Error(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "next-wrong-alg", envelope.AES256GCM)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	_, err = kr.Next(envelope.XChaCha20Poly1305, 1)
	if err == nil {
		t.Error("expected error when passing XChaCha20 to Next, got nil")
	}
}

// ---------------------------------------------------------------------------
// RotateKEK
// ---------------------------------------------------------------------------

func TestRotateKEK_Success(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "rotatekek", envelope.XChaCha20Poly1305)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	newKEK := fastKEK(t, "new-kek-passphrase")
	if err := kr.RotateKEK(newKEK); err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}

	// Reopen with new KEK.
	reopenKEK := fastKEK(t, "new-kek-passphrase")
	kr2, err := keyring.Open(path, reopenKEK)
	if err != nil {
		t.Fatalf("Open after RotateKEK: %v", err)
	}
	defer kr2.Zero()

	dek, _, err := kr2.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK after RotateKEK: %v", err)
	}
	if len(dek) != 32 {
		t.Errorf("dek len = %d, want 32", len(dek))
	}
}

// ---------------------------------------------------------------------------
// DestroyTerm — double-destroy, not-found
// ---------------------------------------------------------------------------

func TestDestroyTerm_DoubleDestroy_Error(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "destroy-double", envelope.XChaCha20Poly1305)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	// Rotate to create term 2.
	newKEK := fastKEK(t, "d2")
	if _, err := kr.RotateTerm(newKEK); err != nil {
		t.Fatalf("RotateTerm: %v", err)
	}

	// Destroy term 1 (retired).
	if err := kr.DestroyTerm(1); err != nil {
		t.Fatalf("DestroyTerm(1) first: %v", err)
	}

	// Destroying again should error.
	err = kr.DestroyTerm(1)
	if err == nil {
		t.Error("expected error on double destroy, got nil")
	}
}

func TestDestroyTerm_NotFound_Error(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "destroy-notfound", envelope.XChaCha20Poly1305)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	// Rotate so active != term 999.
	newKEK := fastKEK(t, "d3")
	if _, err := kr.RotateTerm(newKEK); err != nil {
		t.Fatalf("RotateTerm: %v", err)
	}

	err = kr.DestroyTerm(999)
	if !errors.Is(err, keyring.ErrKeyTermNotFound) {
		t.Errorf("expected ErrKeyTermNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// NextGCMNonce — no GCM state
// ---------------------------------------------------------------------------

func TestNextGCMNonce_NoGCMState_Error(t *testing.T) {
	// XChaCha20 keyring has no GCM state — calling NextGCMNonce should error.
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "no-gcm", envelope.XChaCha20Poly1305)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	_, err = kr.NextGCMNonce(1)
	if err == nil {
		t.Error("expected error when calling NextGCMNonce on XChaCha20 keyring, got nil")
	}
}

// ---------------------------------------------------------------------------
// NextGCMNonce — GCM term not in state
// ---------------------------------------------------------------------------

func TestNextGCMNonce_TermNotInGCMState_Error(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "gcm-term-missing", envelope.AES256GCM)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	// Term 999 doesn't exist in GCM state.
	_, err = kr.NextGCMNonce(999)
	if !errors.Is(err, keyring.ErrKeyTermNotFound) {
		t.Errorf("expected ErrKeyTermNotFound for missing term, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// NextGCMNonce — lease-size > 0 path (allocates a batch)
// ---------------------------------------------------------------------------

func TestNextGCMNonce_LeaseMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	k1 := fastKEK(t, "lease-mode")
	// leaseSize=4 so 4 nonces per disk flush.
	if err := keyring.New(path, k1, envelope.AES256GCM, 4); err != nil {
		t.Fatalf("New: %v", err)
	}

	k2 := fastKEK(t, "lease-mode")
	kr, err := keyring.Open(path, k2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	seen := make(map[string]bool)
	for i := 0; i < 12; i++ { // 3 full leases
		nonce, err := kr.NextGCMNonce(1)
		if err != nil {
			t.Fatalf("NextGCMNonce %d: %v", i, err)
		}
		if seen[string(nonce)] {
			t.Errorf("duplicate nonce at %d: %x", i, nonce)
		}
		seen[string(nonce)] = true
	}
}

// ---------------------------------------------------------------------------
// Open — schema version 0 (too old) should error
// ---------------------------------------------------------------------------

func TestOpen_SchemaVersion_TooOld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	kf := map[string]any{
		"schema_version": 0, // invalid — below minimum of 1
		"algorithm":      "xchacha20-poly1305",
		"active_term":    1,
		"kek_type":       "passphrase",
		"terms":          []map[string]any{},
	}
	b, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	k := fastKEK(t, "version-too-old")
	_, err = keyring.Open(path, k)
	if !errors.Is(err, keyring.ErrKeyringCorrupt) {
		t.Errorf("expected ErrKeyringCorrupt for schema_version=0, got %v", err)
	}
}

func TestOpen_SchemaVersion_TooNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	kf := map[string]any{
		"schema_version": 9999, // too new
		"algorithm":      "xchacha20-poly1305",
		"active_term":    1,
		"kek_type":       "passphrase",
		"terms":          []map[string]any{},
	}
	b, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	k := fastKEK(t, "version-too-new")
	_, err = keyring.Open(path, k)
	if !errors.Is(err, keyring.ErrKeyringCorrupt) {
		t.Errorf("expected ErrKeyringCorrupt for schema_version=9999, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Open — file not found
// ---------------------------------------------------------------------------

func TestOpen_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	k := fastKEK(t, "notfound")
	_, err := keyring.Open(filepath.Join(dir, "missing.json"), k)
	if !errors.Is(err, keyring.ErrKeyringNotFound) {
		t.Errorf("expected ErrKeyringNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// LegacyKEKTypeToRootType — all branches
// ---------------------------------------------------------------------------

func TestLegacyKEKTypeToRootType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kekType  string
		wantType trust.RootType
	}{
		{"passphrase", trust.RootPassphrase},
		{"keychain", trust.RootKeychain},
		{"op", trust.RootOnePassword},
		{"bw", trust.RootBitwarden},
		{"age-env", trust.RootEncryptedFile},
		{"unknown-future", trust.RootType("unknown-future")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.kekType, func(t *testing.T) {
			t.Parallel()
			got := keyring.LegacyKEKTypeToRootType(tc.kekType)
			if got != tc.wantType {
				t.Errorf("LegacyKEKTypeToRootType(%q) = %q, want %q", tc.kekType, got, tc.wantType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RotateTerm — GCM state updated
// ---------------------------------------------------------------------------

func TestRotateTerm_AESGCM_GCMStateUpdated(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "gcm-rotate", envelope.AES256GCM)
	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	newKEK := fastKEK(t, "gcm-rotate-new")
	newTerm, err := kr.RotateTerm(newKEK)
	if err != nil {
		t.Fatalf("RotateTerm: %v", err)
	}
	if newTerm != 2 {
		t.Errorf("newTerm = %d, want 2", newTerm)
	}

	// GCM state for term 2 should be available.
	nonce, err := kr.NextGCMNonce(2)
	if err != nil {
		t.Fatalf("NextGCMNonce(2): %v", err)
	}
	if len(nonce) != 12 {
		t.Errorf("nonce len = %d, want 12", len(nonce))
	}
}

// ---------------------------------------------------------------------------
// TermRecord JSON round-trip
// ---------------------------------------------------------------------------

func TestTermRecord_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	tr := keyring.TermRecord{
		Term:       3,
		Status:     keyring.TermRetired,
		WrappedDEK: []byte{1, 2, 3, 4},
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		KEKType:    "passphrase",
	}
	data, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got keyring.TermRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Term != tr.Term {
		t.Errorf("Term = %d, want %d", got.Term, tr.Term)
	}
	if got.Status != tr.Status {
		t.Errorf("Status = %q, want %q", got.Status, tr.Status)
	}
}
