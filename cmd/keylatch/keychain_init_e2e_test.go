//go:build darwin

package main_test

import (
	"context"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/keychain"
)

// TestKeychainInitE2E is the darwin E2E test for keychain-init flow.
// Uses real /usr/bin/security against paths in t.TempDir().
//
// Skipped unless KEYLATCH_TEST_E2E_KEYCHAIN=1 is set — requires interactive
// macOS keychain access (user password prompt) and /usr/bin/security.
// .
func TestKeychainInitE2E(t *testing.T) {
	if os.Getenv("KEYLATCH_TEST_E2E_KEYCHAIN") == "" {
		t.Skip("skipping keychain E2E test: set KEYLATCH_TEST_E2E_KEYCHAIN=1 with macOS keychain access to run")
	}

	dir := t.TempDir()
	keychainPath := dir + "/test.keychain-db"
	lockPath := dir + "/test.keychain.lock"

	b, err := keychain.Open(keychain.Options{
		KeychainPath: keychainPath,
		LockPath:     lockPath,
		SecurityBin:  "/usr/bin/security",
	})
	if err != nil {
		t.Fatalf("keychain.Open: %v", err)
	}
	defer b.Close()

	ctx := context.Background()

	// Initialize the keychain with a test service.
	if err := b.Init(ctx, "test-service"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Set a credential value.
	path := "default/test-service/api_key"
	want := []byte("e2e-test-value")
	meta := backend.Meta{Path: path, Backend: "keychain", Version: 1}
	if err := b.Set(ctx, path, want, meta); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Get the value back.
	got, _, err := b.Get(ctx, path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("Get: got %q, want %q", got, want)
	}

	// List should return the path without values (no credential bytes in output).
	entries, err := b.List(ctx, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	found := false
	for _, e := range entries {
		if e.Path == path {
			found = true
			if !e.Exists {
				t.Error("List entry.Exists should be true")
			}
		}
	}
	if !found {
		t.Errorf("List: entry %q not found in %v", path, entries)
	}
}
