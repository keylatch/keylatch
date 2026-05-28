// Package testutil provides shared test helpers for keylatch internal packages.
//
// These helpers are only imported from _test.go files or test binaries.
// Production code must not import this package.
package testutil

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
)

// SetupTestKeyring creates a temporary age-env keyring for use in tests that
// exercise dispatch.Select or any path that goes through the file backend factory.
//
// It:
//  1. Creates a random 32-byte age identity file in a temp dir (mode 0o600).
//  2. Sets KEYLATCH_AGE_IDENTITY to the identity file path via t.Setenv.
//  3. Creates a keyring.json in a separate temp dir using the age-env KEK.
//  4. Sets KEYLATCH_KEYRING_PATH to the keyring path via t.Setenv.
//
// All env vars are restored and temp files removed via t.Cleanup automatically.
// Returns the keyring file path for tests that need to pass it explicitly.
func SetupTestKeyring(t *testing.T) string {
	t.Helper()

	// Step 1: create the identity file (raw random bytes, treated as a key material).
	identityDir := t.TempDir()
	identityPath := filepath.Join(identityDir, "test-identity")
	identity := make([]byte, 32)
	if _, err := rand.Read(identity); err != nil {
		t.Fatalf("testutil.SetupTestKeyring: generate identity: %v", err)
	}
	if err := os.WriteFile(identityPath, identity, 0o600); err != nil {
		t.Fatalf("testutil.SetupTestKeyring: write identity: %v", err)
	}

	// Step 2: point the env var at it so EnvAgeIdentityKEK can find the file.
	t.Setenv("KEYLATCH_AGE_IDENTITY", identityPath)

	// Step 3: generate a salt (needed before KEK derivation because age-env uses it).
	saltBytes := make([]byte, 32)
	if _, err := rand.Read(saltBytes); err != nil {
		t.Fatalf("testutil.SetupTestKeyring: generate salt: %v", err)
	}

	// Step 4: derive the KEK from the identity + salt.
	k, err := kek.EnvAgeIdentityKEK(saltBytes)
	if err != nil {
		t.Fatalf("testutil.SetupTestKeyring: EnvAgeIdentityKEK: %v", err)
	}

	// Step 5: create the keyring file.
	krDir := t.TempDir()
	krPath := filepath.Join(krDir, "keyring.json")
	if err := keyring.NewWithSalt(krPath, k, envelope.XChaCha20Poly1305, 0, saltBytes); err != nil {
		t.Fatalf("testutil.SetupTestKeyring: keyring.NewWithSalt: %v", err)
	}

	// Step 6: advertise the keyring path so the file factory can find it.
	t.Setenv("KEYLATCH_KEYRING_PATH", krPath)

	return krPath
}
