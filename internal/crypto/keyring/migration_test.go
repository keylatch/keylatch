package keyring_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
)

// makeTestPassphraseKEK creates a passphrase KEK with deterministic salt for testing.
func makeTestPassphraseKEK(t *testing.T, passphrase string) kek.KEK {
	t.Helper()
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k, err := kek.PassphraseKEK([]byte(passphrase), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}
	return k
}

// legacyFixtureBytes returns a schema version 1 keyring JSON with a single active term.
func legacyFixtureBytes(t *testing.T, wrappedDEK []byte) []byte {
	t.Helper()
	kf := map[string]any{
		"schema_version": 1,
		"algorithm":      "xchacha20-poly1305",
		"active_term":    1,
		"kek_type":       "passphrase",
		"kek_id":         "legacy-passphrase",
		"terms": []map[string]any{
			{
				"term":        1,
				"status":      "active",
				"wrapped_dek": wrappedDEK,
				"created_at":  "2025-01-01T00:00:00Z",
				"kek_type":    "passphrase",
			},
		},
	}
	b, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

// TestMigration_OpensLegacySchemaKeyring verifies that a legacy schema version 1 keyring
// can be opened by the current Open function.
func TestMigration_OpensLegacySchemaKeyring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	pp := makeTestPassphraseKEK(t, "migration-test")
	// Need fresh KEK after zeroing; rebuild.
	rawDEK := make([]byte, 32)
	for i := range rawDEK {
		rawDEK[i] = byte(i + 77)
	}
	wrapped, err := pp.Wrap(rawDEK)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	fixture := legacyFixtureBytes(t, wrapped)
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Fresh KEK for Open (same passphrase, same salt).
	pp2 := makeTestPassphraseKEK(t, "migration-test")
	kr, err := keyring.Open(path, pp2)
	if err != nil {
		t.Fatalf("Open returned error on legacy fixture: %v", err)
	}
	if kr == nil {
		t.Fatal("Open returned nil keyring")
	}

	dek, _, err := kr.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK: %v", err)
	}
	if len(dek) != 32 {
		t.Errorf("DEK length = %d, want 32", len(dek))
	}
}

// TestMigration_RoundTrip verifies that a legacy fixture can be opened and
// DEK recovered correctly (round-trip).
func TestMigration_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	rawDEK := make([]byte, 32)
	for i := range rawDEK {
		rawDEK[i] = byte(i + 42)
	}

	pp1 := makeTestPassphraseKEK(t, "roundtrip-pass")
	wrapped, err := pp1.Wrap(rawDEK)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	fixture := legacyFixtureBytes(t, wrapped)
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Open once (migrates in memory).
	pp2 := makeTestPassphraseKEK(t, "roundtrip-pass")
	kr1, err := keyring.Open(path, pp2)
	if err != nil {
		t.Fatalf("Open(1): %v", err)
	}
	dek1, _, err := kr1.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK(1): %v", err)
	}
	if len(dek1) != 32 {
		t.Errorf("dek1 length = %d, want 32", len(dek1))
	}

	// Verify DEK matches original.
	for i, b := range rawDEK {
		if dek1[i] != b {
			t.Errorf("dek1[%d] = %d, want %d", i, dek1[i], b)
		}
	}

	// Open again — should succeed (idempotent).
	pp3 := makeTestPassphraseKEK(t, "roundtrip-pass")
	kr2, err := keyring.Open(path, pp3)
	if err != nil {
		t.Fatalf("Open(2): %v", err)
	}
	dek2, _, err := kr2.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK(2): %v", err)
	}
	if len(dek2) != 32 {
		t.Errorf("dek2 length = %d, want 32", len(dek2))
	}
}

// TestMigration_UnsupportedKEKType verifies that an unknown kek_type in a v1 keyring
// causes ErrKeyringCorrupt.
func TestMigration_UnsupportedKEKType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")

	kf := map[string]any{
		"schema_version": 1,
		"algorithm":      "xchacha20-poly1305",
		"active_term":    1,
		"kek_type":       "unknown_future_type",
		"terms":          []map[string]any{},
	}
	b, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	salt := make([]byte, 32)
	k, _ := kek.PassphraseKEK([]byte("x"), salt, argon2.Params{
		Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32,
	})
	_, err = keyring.Open(path, k)
	if !errors.Is(err, keyring.ErrKeyringCorrupt) {
		t.Errorf("expected ErrKeyringCorrupt for unknown kek_type, got: %v", err)
	}
}
