package file_test

// helpers_test.go — shared test helpers for the file backend test package.
//
// All tests that exercise Set/Get/SetVersioned/GetVersioned must use a keyring-
// backed backend (T-02-01, T-02-02, T-02-03). openKeyringBackend creates a
// *file.FileBackend with a fresh in-memory keyring suitable for tests.

import (
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// openKeyringBackend returns a FileBackend backed by a fresh XChaCha20-Poly1305
// keyring in t.TempDir(). The backend is registered for t.Cleanup automatically.
func openKeyringBackend(t *testing.T) *file.FileBackend {
	t.Helper()
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.XChaCha20Poly1305)
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatalf("OpenWithKeyring: %v", err)
	}
	t.Cleanup(func() { kr.Zero() })
	return fb
}

// openKeyringBackendInDir is like openKeyringBackend but uses the provided dir.
func openKeyringBackendInDir(t *testing.T, dir string) *file.FileBackend {
	t.Helper()
	kr, _ := buildKeyring(t, dir, envelope.XChaCha20Poly1305)
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatalf("OpenWithKeyring: %v", err)
	}
	t.Cleanup(func() { kr.Zero() })
	return fb
}

// openKeyringBackendAsBackend returns a keyring-backed FileBackend cast to backend.Backend.
func openKeyringBackendAsBackend(t *testing.T) backend.Backend {
	t.Helper()
	return openKeyringBackend(t)
}
