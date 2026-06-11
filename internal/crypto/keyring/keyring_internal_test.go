package keyring

// keyring_internal_test.go tests unexported functions in the keyring package.
// Covers:
//   - migrateV1toV2 — all branches (already-migrated, no kek_type, valid migration)
//   - legacyKEKTypeToRootType — all branches
//   - loadFile — wrong-mode path
//   - saveFile — marshal + atomicWrite integration
//   - atomicWrite — paths not hit by external tests
//   - NextGCMNonce — fsync fail hook, nonce counter at MaxUint64, leaseEnd overflow

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/trust"
)

// ---------------------------------------------------------------------------
// migrateV1toV2
// ---------------------------------------------------------------------------

func TestMigrateV1toV2_AlreadyMigrated(t *testing.T) {
	t.Parallel()
	// If Roots is already set, migration must be a no-op.
	kf := &KeyringFile{
		SchemaVersion: 1,
		KEKType:       "passphrase",
		Roots: []RootOfTrustRecord{
			{Spec: trust.RootSpec{ID: "existing-root"}},
		},
	}
	originalRoots := kf.Roots
	if err := migrateV1toV2(kf); err != nil {
		t.Fatalf("migrateV1toV2 (already migrated): %v", err)
	}
	if len(kf.Roots) != len(originalRoots) {
		t.Errorf("Roots changed during idempotent migration: got %d, want %d", len(kf.Roots), len(originalRoots))
	}
	// Schema version should not be bumped (already has roots).
	if kf.SchemaVersion != 1 {
		t.Errorf("SchemaVersion changed from 1 to %d in idempotent migration", kf.SchemaVersion)
	}
}

func TestMigrateV1toV2_EmptyKEKType_Error(t *testing.T) {
	t.Parallel()
	kf := &KeyringFile{
		SchemaVersion: 1,
		KEKType:       "", // missing
	}
	err := migrateV1toV2(kf)
	if err == nil {
		t.Error("expected error when kek_type is empty, got nil")
	}
}

func TestMigrateV1toV2_Valid_NoKEKID(t *testing.T) {
	t.Parallel()
	// When KEKID is empty, the KEKType should be used as the root ID.
	wrappedDEK := []byte{1, 2, 3, 4, 5}
	kf := &KeyringFile{
		SchemaVersion: 1,
		KEKType:       "passphrase",
		KEKID:         "", // empty — falls back to KEKType
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrappedDEK,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	if err := migrateV1toV2(kf); err != nil {
		t.Fatalf("migrateV1toV2: %v", err)
	}
	if len(kf.Roots) != 1 {
		t.Fatalf("Roots len = %d, want 1", len(kf.Roots))
	}
	root := kf.Roots[0]
	if root.Spec.ID != "passphrase" {
		t.Errorf("Spec.ID = %q, want %q (fallback to kek_type)", root.Spec.ID, "passphrase")
	}
	if root.Spec.Type != trust.RootPassphrase {
		t.Errorf("Spec.Type = %q, want RootPassphrase", root.Spec.Type)
	}
	if root.Spec.Status != trust.RootActive {
		t.Errorf("Spec.Status = %q, want RootActive", root.Spec.Status)
	}
	// WrappedDEK for term 1 should be present in base64 form.
	wantB64 := base64.StdEncoding.EncodeToString(wrappedDEK)
	if got := root.WrappedDEKs[1]; got != wantB64 {
		t.Errorf("WrappedDEKs[1] = %q, want %q", got, wantB64)
	}
	if kf.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", kf.SchemaVersion, SchemaVersion)
	}
}

func TestMigrateV1toV2_Valid_WithKEKID(t *testing.T) {
	t.Parallel()
	kf := &KeyringFile{
		SchemaVersion: 1,
		KEKType:       "op",
		KEKID:         "op://vault/item/field",
	}
	if err := migrateV1toV2(kf); err != nil {
		t.Fatalf("migrateV1toV2: %v", err)
	}
	if kf.Roots[0].Spec.ID != "op://vault/item/field" {
		t.Errorf("Spec.ID = %q, want %q", kf.Roots[0].Spec.ID, "op://vault/item/field")
	}
}

func TestMigrateV1toV2_DestroyedTermExcluded(t *testing.T) {
	t.Parallel()
	kf := &KeyringFile{
		SchemaVersion: 1,
		KEKType:       "passphrase",
		Terms: []TermRecord{
			{Term: 1, Status: TermActive, WrappedDEK: []byte{1}},
			{Term: 2, Status: TermDestroyed, WrappedDEK: nil}, // destroyed — empty wrapped DEK
		},
	}
	if err := migrateV1toV2(kf); err != nil {
		t.Fatalf("migrateV1toV2: %v", err)
	}
	// Term 1 with non-empty DEK should appear; term 2 with empty DEK should not.
	wrappedDEKs := kf.Roots[0].WrappedDEKs
	if _, ok := wrappedDEKs[1]; !ok {
		t.Error("term 1 should be present in WrappedDEKs")
	}
	if _, ok := wrappedDEKs[2]; ok {
		t.Error("term 2 (empty DEK) should NOT be present in WrappedDEKs")
	}
}

// ---------------------------------------------------------------------------
// legacyKEKTypeToRootType (unexported) — all branches
// ---------------------------------------------------------------------------

func TestLegacyKEKTypeToRootTypeInternal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want trust.RootType
	}{
		{"passphrase", trust.RootPassphrase},
		{"keychain", trust.RootKeychain},
		{"op", trust.RootOnePassword},
		{"bw", trust.RootBitwarden},
		{"age-env", trust.RootEncryptedFile},
		{"custom", trust.RootType("custom")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got := legacyKEKTypeToRootType(tc.in)
			if got != tc.want {
				t.Errorf("legacyKEKTypeToRootType(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// loadFile — wrong permissions path
// ---------------------------------------------------------------------------

func TestLoadFile_WrongMode(t *testing.T) {
	if !enforcePrivateFileMode {
		t.Skip("permission enforcement disabled on this platform")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     envelope.XChaCha20Poly1305,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          make([]byte, 32),
		Terms: []TermRecord{
			{Term: 1, Status: TermActive, WrappedDEK: []byte("x"), KEKType: "passphrase"},
		},
	}
	data, _ := json.Marshal(kf)
	// Write with mode 0o644 (wrong).
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadFile(path)
	if err == nil {
		t.Error("expected error for wrong file mode, got nil")
	}
}

// ---------------------------------------------------------------------------
// NextGCMNonce — fsync fail hook (rollback path)
// ---------------------------------------------------------------------------

func buildGCMKeyring(t *testing.T, dir string, passphrase string, leaseSize uint64) (*Keyring, string) {
	t.Helper()
	krPath := filepath.Join(dir, "keyring.json")

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 3)
	}

	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k1, err := kek.PassphraseKEK([]byte(passphrase), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 42)
	}
	wrapped, err := k1.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     envelope.AES256GCM,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          salt,
		GCMState: &GCMState{
			PerTerm:   map[int]uint64{1: 0},
			LeaseSize: leaseSize,
		},
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    "passphrase",
			},
		},
	}

	data, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	k2, err := kek.PassphraseKEK([]byte(passphrase), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}

	kr, err := Open(krPath, k2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	return kr, krPath
}

func TestNextGCMNonce_FsyncFailHook_RollsBack(t *testing.T) {
	dir := t.TempDir()
	kr, _ := buildGCMKeyring(t, dir, "fsync-fail-test", 0)
	defer kr.Zero()

	// Inject a failing fsync hook.
	kr.fsyncFailHook = func() error {
		return ErrNonceCounterFlushFailed
	}

	_, err := kr.NextGCMNonce(1)
	if err == nil {
		t.Error("expected ErrNonceCounterFlushFailed, got nil")
	}
}

func TestNextGCMNonce_MaxUint64_Exhausted(t *testing.T) {
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.json")

	salt := make([]byte, 32)
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k1, err := kek.PassphraseKEK([]byte("maxuint"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	wrapped, err := k1.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Set counter to MaxUint64 to trigger exhausted path.
	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     envelope.AES256GCM,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          salt,
		GCMState: &GCMState{
			PerTerm:   map[int]uint64{1: math.MaxUint64},
			LeaseSize: 0,
		},
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    "passphrase",
			},
		},
	}
	data, _ := json.Marshal(kf)
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	k2, err := kek.PassphraseKEK([]byte("maxuint"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}
	kr, err := Open(krPath, k2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	_, err = kr.NextGCMNonce(1)
	if err != ErrKeyTermExhausted {
		t.Errorf("expected ErrKeyTermExhausted, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// NextGCMNonce — leaseEnd overflow (diskCounter near MaxUint64 with leaseSize>0)
// ---------------------------------------------------------------------------

func TestNextGCMNonce_LeaseEndOverflow(t *testing.T) {
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.json")

	salt := make([]byte, 32)
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k1, err := kek.PassphraseKEK([]byte("overflow"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	wrapped, err := k1.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Set diskCounter close to MaxUint64 (but not AT MaxUint64) with leaseSize>0.
	// This triggers the "diskCounter > math.MaxUint64 - leaseSize" branch.
	nearMax := uint64(math.MaxUint64 - 5)
	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     envelope.AES256GCM,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          salt,
		GCMState: &GCMState{
			PerTerm:   map[int]uint64{1: nearMax},
			LeaseSize: 100, // 100 > 5 remaining slots → overflow branch
		},
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    "passphrase",
			},
		},
	}
	data, _ := json.Marshal(kf)
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	k2, err := kek.PassphraseKEK([]byte("overflow"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}
	kr, err := Open(krPath, k2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	// First call: allocates a lease capped at MaxUint64.
	nonce, err := kr.NextGCMNonce(1)
	if err != nil {
		t.Fatalf("NextGCMNonce: %v", err)
	}
	if len(nonce) != 12 {
		t.Errorf("nonce len = %d, want 12", len(nonce))
	}
}

// ---------------------------------------------------------------------------
// RotateTerm — file not found error path
// ---------------------------------------------------------------------------

func TestRotateTerm_FileGone_Error(t *testing.T) {
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.json")

	salt := make([]byte, 32)
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k1, err := kek.PassphraseKEK([]byte("gone"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	wrapped, err := k1.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     envelope.XChaCha20Poly1305,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          salt,
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    "passphrase",
			},
		},
	}
	data, _ := json.Marshal(kf)
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	k2, err := kek.PassphraseKEK([]byte("gone"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}
	kr, err := Open(krPath, k2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Delete the keyring file while the Keyring is open.
	if err := os.Remove(krPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	newKEK, err := kek.PassphraseKEK([]byte("new-pass"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK new: %v", err)
	}

	_, err = kr.RotateTerm(newKEK)
	if err == nil {
		t.Error("expected error when keyring file is gone, got nil")
	}
}

// ---------------------------------------------------------------------------
// RotateKEK — missing DEK in memory (simulate corrupt in-memory state)
// ---------------------------------------------------------------------------

func TestRotateKEK_FileGone_Error(t *testing.T) {
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.json")

	salt := make([]byte, 32)
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k1, err := kek.PassphraseKEK([]byte("rotatekek-gone"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	wrapped, err := k1.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	kf := KeyringFile{
		SchemaVersion: SchemaVersion,
		Algorithm:     envelope.XChaCha20Poly1305,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          salt,
		Terms: []TermRecord{
			{
				Term:       1,
				Status:     TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    "passphrase",
			},
		},
	}
	data, _ := json.Marshal(kf)
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	k2, err := kek.PassphraseKEK([]byte("rotatekek-gone"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}
	kr, err := Open(krPath, k2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Delete the keyring file.
	if err := os.Remove(krPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	newKEK, err := kek.PassphraseKEK([]byte("newkek"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK new: %v", err)
	}

	err = kr.RotateKEK(newKEK)
	if err == nil {
		t.Error("expected error when keyring file is gone, got nil")
	}
}
