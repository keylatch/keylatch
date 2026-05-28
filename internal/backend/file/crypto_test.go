package file_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// buildKeyring creates a keyring file in dir and returns the keyring and its KEK.
func buildKeyring(t *testing.T, dir string, alg envelope.Algorithm) (*keyring.Keyring, kek.KEK) {
	t.Helper()
	krDir := filepath.Join(dir, "keyring")
	if err := os.MkdirAll(krDir, 0o700); err != nil {
		t.Fatalf("mkdir keyring: %v", err)
	}
	krPath := filepath.Join(krDir, "keyring.json")

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 5)
	}
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}

	k, err := kek.PassphraseKEK([]byte("test-pass"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 99)
	}
	wrapped, _ := k.Wrap(dek)

	kf := keyring.KeyringFile{
		SchemaVersion: keyring.SchemaVersion,
		Algorithm:     alg,
		ActiveTerm:    1,
		KEKType:       "passphrase",
		Salt:          salt,
		Terms: []keyring.TermRecord{
			{
				Term:       1,
				Status:     keyring.TermActive,
				WrappedDEK: wrapped,
				CreatedAt:  time.Now().UTC().Format(time.RFC3339),
				KEKType:    "passphrase",
			},
		},
	}
	if alg == envelope.AES256GCM {
		kf.GCMState = &keyring.GCMState{PerTerm: map[int]uint64{1: 0}, LeaseSize: 0}
	}

	data, _ := json.Marshal(kf)
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}

	// Re-derive KEK since passphrase was zeroed.
	k2, err := kek.PassphraseKEK([]byte("test-pass"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}

	kr, err := keyring.Open(krPath, k2)
	if err != nil {
		t.Fatalf("keyring.Open: %v", err)
	}
	return kr, k2
}

func TestAEADSetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.XChaCha20Poly1305)
	defer kr.Zero()

	fb, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	canonical := "default/test/aead_key"
	now := time.Now().UTC()

	vm := vmeta.VersionMeta{
		Version:   1,
		CreatedAt: now,
		AAD: vmeta.AADBinding{
			SchemaVersion: vmeta.CurrentSchemaVersion,
			Namespace:     "default",
			Path:          canonical,
			Version:       1,
			KeyTerm:       1,
			BackendID:     fb.ID(),
			CreatedAt:     now,
			Algorithm:     string(envelope.XChaCha20Poly1305),
		},
	}

	plaintext := []byte("super-secret-api-key-value")

	// Encrypt and write.
	if err := fb.SetVersionedEncrypted(ctx, canonical, vm, plaintext, kr); err != nil {
		t.Fatalf("SetVersionedEncrypted: %v", err)
	}

	// Decrypt and read.
	got, err := fb.GetVersionedEncrypted(ctx, canonical, vm, kr)
	if err != nil {
		t.Fatalf("GetVersionedEncrypted: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestGetAADMismatch(t *testing.T) {
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.XChaCha20Poly1305)
	defer kr.Zero()

	fb, _ := file.Open(file.Options{Dir: dir})
	ctx := context.Background()
	canonical := "default/test/mismatch_key"
	now := time.Now().UTC()

	vm := vmeta.VersionMeta{
		Version:   1,
		CreatedAt: now,
		AAD: vmeta.AADBinding{
			SchemaVersion: vmeta.CurrentSchemaVersion,
			Namespace:     "default",
			Path:          canonical,
			Version:       1,
			KeyTerm:       1,
			BackendID:     fb.ID(),
			CreatedAt:     now,
			Algorithm:     string(envelope.XChaCha20Poly1305),
		},
	}

	plaintext := []byte("value-for-aad-mismatch-test")
	fb.SetVersionedEncrypted(ctx, canonical, vm, plaintext, kr)

	// Case 1: path changed (AAD mismatch).
	vmWrongPath := vm
	vmWrongPath.AAD.Path = "default/other/path"
	_, err := fb.GetVersionedEncrypted(ctx, canonical, vmWrongPath, kr)
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("wrong path: expected ErrAEADAuthFailed, got %v", err)
	}

	// Case 2: version changed (AAD mismatch).
	vmWrongVersion := vm
	vmWrongVersion.AAD.Version = 99
	_, err = fb.GetVersionedEncrypted(ctx, canonical, vmWrongVersion, kr)
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("wrong version: expected ErrAEADAuthFailed, got %v", err)
	}

	// Case 3: backend_id changed.
	vmWrongBackend := vm
	vmWrongBackend.AAD.BackendID = "file:/different/dir"
	_, err = fb.GetVersionedEncrypted(ctx, canonical, vmWrongBackend, kr)
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("wrong backend: expected ErrAEADAuthFailed, got %v", err)
	}
}

func TestInitKeyring(t *testing.T) {
	dir := t.TempDir()
	salt := make([]byte, 32)
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k, err := kek.PassphraseKEK([]byte("init-pass"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	ctx := context.Background()
	if err := file.InitKeyring(ctx, dir, k, envelope.XChaCha20Poly1305); err != nil {
		t.Fatalf("InitKeyring: %v", err)
	}

	// Verify keyring file exists and is readable.
	krPath := filepath.Join(dir, "keyring", "keyring.json")
	if _, err := os.Stat(krPath); err != nil {
		t.Errorf("keyring.json not found: %v", err)
	}

	// Open the keyring with the same KEK.
	k2, _ := kek.PassphraseKEK([]byte("init-pass"), salt, params)
	kr, err := keyring.Open(krPath, k2)
	if err != nil {
		t.Fatalf("keyring.Open after init: %v", err)
	}
	defer kr.Zero()

	_, term, err := kr.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK: %v", err)
	}
	if term != 1 {
		t.Errorf("term = %d, want 1", term)
	}

	// Idempotent: calling InitKeyring again should be a no-op.
	k3, _ := kek.PassphraseKEK([]byte("init-pass"), salt, params)
	if err := file.InitKeyring(ctx, dir, k3, envelope.XChaCha20Poly1305); err != nil {
		t.Errorf("InitKeyring idempotent: %v", err)
	}
}

// TestPhase5ValuesOpaqueWithoutKeyring verifies that values written through the
// encrypted backend are not readable as plaintext (S5-1).
func TestPhase5ValuesOpaqueWithoutKeyring(t *testing.T) {
	dir := t.TempDir()
	kr, k := buildKeyring(t, dir, envelope.XChaCha20Poly1305)
	defer kr.Zero()

	// Open an encrypted backend.
	fbEnc, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatalf("OpenWithKeyring: %v", err)
	}

	ctx := context.Background()
	canonical := "default/test/opaque_key"
	version := 1
	plaintext := []byte("KEYLATCH_CANARY_PHASE5_0xDEADBEEF")

	// Write through the encrypted backend.
	if err := fbEnc.SetVersioned(ctx, canonical, version, plaintext); err != nil {
		t.Fatalf("SetVersioned encrypted: %v", err)
	}

	// Read the raw on-disk file bytes directly.
	p := filepath.Join(dir, "values", "default", "test", "opaque_key", "1")
	rawBytes, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile raw: %v", err)
	}

	// The raw bytes must NOT be equal to the plaintext.
	if bytes.Equal(rawBytes, plaintext) {
		t.Error("raw bytes on disk are identical to plaintext — encryption is not applied")
	}

	// The raw bytes must NOT contain the plaintext canary.
	if bytes.Contains(rawBytes, plaintext) {
		t.Error("raw bytes contain plaintext canary — encryption is not applied")
	}

	// Open a second backend WITHOUT a keyring (plaintext mode).
	// GetVersioned should return ErrNotFound or an error — not plaintext.
	fbPlain, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open plain: %v", err)
	}
	rawValue, err := fbPlain.GetVersioned(ctx, canonical, version)
	if err != nil {
		// Expected: raw backend fails to read (ErrNotFound or similar). Fine.
		t.Logf("plain GetVersioned returned error (expected): %v", err)
	} else {
		// If it succeeds, it must NOT return the plaintext.
		if bytes.Equal(rawValue, plaintext) {
			t.Error("plain backend returned plaintext — encrypted backend stored unencrypted data")
		}
	}

	// The encrypted backend must still be able to decrypt.
	// Re-open with a fresh keyring instance.
	kr2, err := keyring.Open(
		filepath.Join(dir, "keyring", "keyring.json"),
		k,
	)
	if err != nil {
		t.Fatalf("keyring.Open for re-read: %v", err)
	}
	defer kr2.Zero()

	fbEnc2, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr2)
	if err != nil {
		t.Fatalf("OpenWithKeyring 2: %v", err)
	}
	got, err := fbEnc2.GetVersioned(ctx, canonical, version)
	if err != nil {
		t.Fatalf("GetVersioned encrypted: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypt round-trip mismatch: got %q, want %q", got, plaintext)
	}
}
