package file_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/backendtest"
)

func TestFileBackend_ComplianceHarness(t *testing.T) {
	backendtest.RunBackendComplianceTests(t, func() backend.Backend {
		return openKeyringBackendAsBackend(t)
	})
}

func TestFileBackend_RoundTrip(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	path := "default/ai/openrouter/api_key"
	want := []byte("sk-test-1234")
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	if err := b.Set(context.Background(), path, want, meta); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, _, err := b.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, want)
	}
}

func TestFileBackend_NotFound(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	_, _, err := b.Get(context.Background(), "no/such/path")
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("Get missing path: got %v, want ErrNotFound", err)
	}
}

// TestFileBackend_NoKeyring_ReturnsBootstrapRequired verifies that Set/Get
// without a keyring returns ErrBootstrapRequired.
// The file backend production path requires a keyring (OpenWithKeyring).
// Without a keyring, both Set and Get return ErrBootstrapRequired and direct the
// user to run 'keylatch bootstrap'.
func TestFileBackend_NoKeyring_ReturnsBootstrapRequired(t *testing.T) {
	b, err := file.Open(file.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("file.Open: %v", err)
	}
	defer b.Close()

	path := "default/test/no-keyring"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	setErr := b.Set(context.Background(), path, []byte("val"), meta)
	if !errors.Is(setErr, backend.ErrBootstrapRequired) {
		t.Errorf("Set without keyring: got %v, want ErrBootstrapRequired", setErr)
	}

	_, _, getErr := b.Get(context.Background(), path)
	if !errors.Is(getErr, backend.ErrBootstrapRequired) {
		t.Errorf("Get without keyring: got %v, want ErrBootstrapRequired", getErr)
	}
}

func TestFileBackend_FileModes(t *testing.T) {
	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	path := "default/test/secret"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}
	if err := b.Set(context.Background(), path, []byte("val"), meta); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Check manifest.json mode.
	manifestPath := filepath.Join(dir, "manifest.json")
	assertPrivateFileMode(t, manifestPath, "manifest.json")

	// Check value.enc mode.
	encPath := filepath.Join(dir, "default", "test", "secret", "value.enc")
	assertPrivateFileMode(t, encPath, "value.enc")
}

func TestFileBackend_ManifestPersistence(t *testing.T) {
	dir := t.TempDir()

	// Write with first backend instance (uses a keyring in dir/keyring/).
	b1 := openKeyringBackendInDir(t, dir)
	path := "default/persistence/test"
	want := []byte("persistent-value")
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}
	if err := b1.Set(context.Background(), path, want, meta); err != nil {
		t.Fatalf("Set: %v", err)
	}
	b1.Close()

	// Re-open same directory with a new keyring-backed backend.
	b2 := openKeyringBackendInDir(t, dir)
	defer b2.Close()

	got, _, err := b2.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("persistence mismatch: got %q, want %q", got, want)
	}
}

func TestFileBackend_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	path := "default/atomic/test"
	want := []byte("atomic-value-content")
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	if err := b.Set(context.Background(), path, want, meta); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// No temp files should remain in the root directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}

	// The written value should survive a round-trip.
	got, _, err := b.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("atomic write round-trip: got %q, want %q", got, want)
	}
}

func TestFileBackend_ListDoesNotReadValueFiles(t *testing.T) {
	b := openKeyringBackend(t)
	defer b.Close()

	dir := b.Dir()

	paths := []string{"default/ai/openrouter/api_key", "default/ai/anthropic/api_key"}
	for _, p := range paths {
		meta := backend.Meta{Path: p, Backend: "file", Version: 1}
		if err := b.Set(context.Background(), p, []byte("secret"), meta); err != nil {
			t.Fatalf("Set %q: %v", p, err)
		}
	}

	// Remove value.enc files — List should still succeed (only reads manifest).
	encPath := filepath.Join(dir, "default", "ai", "openrouter", "api_key", "value.enc")
	if err := os.Remove(encPath); err != nil {
		t.Fatalf("Remove value.enc: %v", err)
	}

	entries, err := b.List(context.Background(), "default/ai/")
	if err != nil {
		t.Fatalf("List after removing value.enc: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("List: got %d entries, want 2", len(entries))
	}
}

func TestFileBackend_CanarySecret(t *testing.T) {
	// Canary test: the canary value must NOT appear in plaintext on disk.
	// v1.0.0: AEAD encryption, so this is always true.
	canary := "KEYLATCH_CANARY_PHASE1_0xDEADBEEF"
	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	path := "default/test/canary"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}
	if err := b.Set(context.Background(), path, []byte(canary), meta); err != nil {
		t.Fatalf("Set canary: %v", err)
	}

	// Read the raw on-disk value.enc — it must NOT contain the plaintext canary.
	encPath := filepath.Join(dir, "default", "test", "canary", "value.enc")
	raw, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("ReadFile value.enc: %v", err)
	}

	if bytes.Contains(raw, []byte(canary)) {
		t.Error("canary secret appears in plaintext on disk (value.enc must be AEAD-encrypted)")
	}
	if string(raw) == canary {
		t.Error("canary secret appears as-is on disk")
	}
}

// TestFileBackend_AEADRoundtrip verifies that Set encrypts with AEAD and
// Get decrypts to the original plaintext. The on-disk value.enc must not contain
// the plaintext.
func TestFileBackend_AEADRoundtrip(t *testing.T) {
	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	path := "default/test/aead-roundtrip"
	want := []byte("sk-test-aead-roundtrip-0xDEADBEEF")
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	if err := b.Set(context.Background(), path, want, meta); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Read back via Get — must equal original plaintext.
	got, _, err := b.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("AEAD round-trip mismatch: got %q, want %q", got, want)
	}

	// On-disk value.enc must not contain the plaintext (CRIT-01).
	encPath := filepath.Join(dir, "default", "test", "aead-roundtrip", "value.enc")
	raw, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("ReadFile value.enc: %v", err)
	}
	if bytes.Contains(raw, want) {
		t.Error("CRIT-01: plaintext found in value.enc — AEAD encryption not applied")
	}
	b64Want := []byte(base64.StdEncoding.EncodeToString(want))
	if bytes.Contains(raw, b64Want) {
		t.Error("CRIT-01: base64 of plaintext found in value.enc")
	}
	b64WantURL := []byte(base64.URLEncoding.EncodeToString(want))
	if bytes.Contains(raw, b64WantURL) {
		t.Error("CRIT-01: base64url of plaintext found in value.enc")
	}
}

// TestFileBackend_PathTraversalRejected verifies that path-traversal inputs
// that would escape the vault root are rejected with a clear error for both Set
// and Delete operations.
func TestFileBackend_PathTraversalRejected(t *testing.T) {
	traversalPaths := []string{
		"../escape",
		"../../etc/passwd",
		"default/../../escape",
	}

	t.Run("Set", func(t *testing.T) {
		b := openKeyringBackend(t)
		defer b.Close()

		for _, p := range traversalPaths {
			p := p
			t.Run(p, func(t *testing.T) {
				meta := backend.Meta{Backend: "file", Version: 1}
				err := b.Set(context.Background(), p, []byte("val"), meta)
				if err == nil {
					t.Fatalf("Set(%q): expected path-escape error, got nil", p)
				}
				if !bytes.Contains([]byte(err.Error()), []byte("escapes vault root")) {
					t.Errorf("Set(%q): expected 'escapes vault root' error, got: %v", p, err)
				}
			})
		}
	})

	t.Run("Delete", func(t *testing.T) {
		b := openKeyringBackend(t)
		defer b.Close()

		for _, p := range traversalPaths {
			p := p
			t.Run(p, func(t *testing.T) {
				err := b.Delete(context.Background(), p)
				if err == nil {
					t.Fatalf("Delete(%q): expected path-escape error, got nil", p)
				}
				if !bytes.Contains([]byte(err.Error()), []byte("escapes vault root")) {
					t.Errorf("Delete(%q): expected 'escapes vault root' error, got: %v", p, err)
				}
			})
		}
	})
}
