package keyring_test

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
)

// buildTestKeyring creates a keyring file in dir with a single active term
// wrapped under the given passphrase, and returns the path and the KEK.
func buildTestKeyring(t *testing.T, dir string, passphrase string, alg envelope.Algorithm) (string, kek.KEK) {
	t.Helper()
	krPath := filepath.Join(dir, "keyring.json")

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	params := argon2.Params{
		Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32,
	}

	k, err := kek.PassphraseKEK([]byte(passphrase), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 42)
	}
	wrapped, err := k.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

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
		kf.GCMState = &keyring.GCMState{
			PerTerm:   map[int]uint64{1: 0},
			LeaseSize: 0, // strict mode for tests
		}
	}

	data, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("marshal keyring: %v", err)
	}
	if err := os.WriteFile(krPath, data, 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}

	// Need a fresh KEK since we zeroed the passphrase above.
	k2, err := kek.PassphraseKEK([]byte(passphrase), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK2: %v", err)
	}
	return krPath, k2
}

func TestOpenCorrectKEK(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "correct-pass", envelope.XChaCha20Poly1305)

	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
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

func TestOpenWrongKEK(t *testing.T) {
	dir := t.TempDir()
	path, _ := buildTestKeyring(t, dir, "correct-pass", envelope.XChaCha20Poly1305)

	// Create a different KEK (different passphrase).
	salt := make([]byte, 32)
	wrongKEK, err := kek.PassphraseKEK([]byte("wrong-pass"), salt, argon2.Params{
		Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32,
	})
	if err != nil {
		t.Fatalf("wrong KEK: %v", err)
	}

	_, err = keyring.Open(path, wrongKEK)
	if !errors.Is(err, keyring.ErrKEKMismatch) {
		t.Errorf("expected ErrKEKMismatch, got %v", err)
	}
}

func TestOpenCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	if err := os.WriteFile(path, []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	salt := make([]byte, 32)
	k, _ := kek.PassphraseKEK([]byte("p"), salt, argon2.Params{
		Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32,
	})

	_, err := keyring.Open(path, k)
	if !errors.Is(err, keyring.ErrKeyringCorrupt) {
		t.Errorf("expected ErrKeyringCorrupt, got %v", err)
	}
}

func TestDEKForTermLifecycle(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "passphrase", envelope.XChaCha20Poly1305)

	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	// Term 1 should be findable.
	dek, err := kr.DEKForTerm(1)
	if err != nil {
		t.Fatalf("DEKForTerm(1): %v", err)
	}
	if len(dek) != 32 {
		t.Errorf("dek len = %d", len(dek))
	}

	// Non-existent term.
	_, err = kr.DEKForTerm(999)
	if !errors.Is(err, keyring.ErrKeyTermNotFound) {
		t.Errorf("term 999: expected ErrKeyTermNotFound, got %v", err)
	}
}

func TestZeroClears(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "pass", envelope.XChaCha20Poly1305)

	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Get the DEK reference before zeroing.
	dek, _, err := kr.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK: %v", err)
	}

	// Zero all DEKs.
	kr.Zero()

	// The slice backing array should be zeroed.
	for i, b := range dek {
		if b != 0 {
			t.Errorf("dek[%d] = 0x%02x after Zero(), want 0x00", i, b)
		}
	}
}

func TestAtomicWriteConsistency(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "pass", envelope.XChaCha20Poly1305)

	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Verify we can rotate term successfully.
	salt := make([]byte, 32)
	newKEK, _ := kek.PassphraseKEK([]byte("new-pass"), salt, argon2.Params{
		Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32,
	})
	newTerm, err := kr.RotateTerm(newKEK)
	if err != nil {
		t.Fatalf("RotateTerm: %v", err)
	}
	if newTerm != 2 {
		t.Errorf("newTerm = %d, want 2", newTerm)
	}

	// The keyring file should be loadable.
	kf, err := openKeyringFile(path)
	if err != nil {
		t.Fatalf("load after rotate: %v", err)
	}
	if kf.ActiveTerm != 2 {
		t.Errorf("ActiveTerm = %d, want 2", kf.ActiveTerm)
	}
	if len(kf.Terms) != 2 {
		t.Errorf("Terms len = %d, want 2", len(kf.Terms))
	}
}

func TestDestroyTermRefusesActive(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "pass", envelope.XChaCha20Poly1305)

	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Destroying the active term (1) should fail.
	err = kr.DestroyTerm(1)
	if err == nil {
		t.Error("expected error when destroying active term")
	}
}

func TestDestroyTermMakesUnreadable(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "pass", envelope.XChaCha20Poly1305)

	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Rotate to create term 2.
	salt := make([]byte, 32)
	newKEK, _ := kek.PassphraseKEK([]byte("new"), salt, argon2.Params{
		Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32,
	})
	_, err = kr.RotateTerm(newKEK)
	if err != nil {
		t.Fatalf("RotateTerm: %v", err)
	}

	// Now destroy term 1.
	if err := kr.DestroyTerm(1); err != nil {
		t.Fatalf("DestroyTerm(1): %v", err)
	}

	// Trying to use term 1 should return ErrKeyTermDestroyed.
	_, err = kr.DEKForTerm(1)
	if !errors.Is(err, keyring.ErrKeyTermDestroyed) {
		t.Errorf("expected ErrKeyTermDestroyed, got %v", err)
	}
}

func TestNextGCMNonceMonotonic(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "pass", envelope.AES256GCM)

	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		nonce, err := kr.NextGCMNonce(1)
		if err != nil {
			t.Fatalf("NextGCMNonce iteration %d: %v", i, err)
		}
		key := string(nonce)
		if seen[key] {
			t.Errorf("duplicate nonce at iteration %d: %x", i, nonce)
		}
		seen[key] = true
	}
}

// TestNextGCMNonceConcurrentNoDuplicates verifies that 100 goroutines
// each calling NextGCMNonce concurrently produce no duplicate (term, counter)
// pairs. This exercises the inter-process flock path indirectly via the
// in-process mutex — all goroutines share the same *Keyring instance.
func TestNextGCMNonceConcurrentNoDuplicates(t *testing.T) {
	dir := t.TempDir()
	path, k := buildTestKeyring(t, dir, "pass", envelope.AES256GCM)

	kr, err := keyring.Open(path, k)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer kr.Zero()

	const goroutines = 100
	nonces := make(chan string, goroutines)
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			nonce, err := kr.NextGCMNonce(1)
			if err != nil {
				errs <- err
				return
			}
			nonces <- string(nonce)
		}()
	}

	seen := make(map[string]bool, goroutines)
	for i := 0; i < goroutines; i++ {
		select {
		case err := <-errs:
			t.Errorf("NextGCMNonce error: %v", err)
		case n := <-nonces:
			if seen[n] {
				t.Errorf("duplicate nonce produced: %x", []byte(n))
			}
			seen[n] = true
		}
	}
	if len(seen) != goroutines {
		t.Errorf("expected %d unique nonces, got %d", goroutines, len(seen))
	}
}

// openKeyringFile is a test helper that loads and parses a keyring file directly.
func openKeyringFile(path string) (keyring.KeyringFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return keyring.KeyringFile{}, err
	}
	var kf keyring.KeyringFile
	return kf, json.Unmarshal(data, &kf)
}
