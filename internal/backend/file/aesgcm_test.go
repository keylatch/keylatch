// Package file_test — AES-256-GCM algorithm path tests.
// These tests exercise the AES-GCM switch arms in SetVersionedEncrypted,
// GetVersionedEncrypted, Set, Get, and InitKeyring.
package file_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// openAESGCMKeyringBackend creates a FileBackend backed by an AES-256-GCM keyring.
func openAESGCMKeyringBackend(t *testing.T) *file.FileBackend {
	t.Helper()
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.AES256GCM)
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatalf("OpenWithKeyring (AES-GCM): %v", err)
	}
	t.Cleanup(func() { kr.Zero() })
	return fb
}

// openAESGCMKeyringBackendInDir creates a FileBackend in a specific dir with AES-GCM.
func openAESGCMKeyringBackendInDir(t *testing.T, dir string) *file.FileBackend {
	t.Helper()
	kr, _ := buildKeyring(t, dir, envelope.AES256GCM)
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatalf("OpenWithKeyring (AES-GCM) in dir: %v", err)
	}
	t.Cleanup(func() { kr.Zero() })
	return fb
}

// TestAESGCM_SetVersionedEncrypted_RoundTrip verifies the AES-256-GCM path
// in SetVersionedEncrypted and GetVersionedEncrypted.
func TestAESGCM_SetVersionedEncrypted_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.AES256GCM)
	defer kr.Zero()

	fb, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer fb.Close()

	ctx := context.Background()
	canonical := "default/test/aesgcm_key"

	_, term, err := kr.ActiveDEK()
	if err != nil {
		t.Fatalf("ActiveDEK: %v", err)
	}

	vm := vmeta.VersionMeta{
		Version: 1,
		AAD: vmeta.AADBinding{
			SchemaVersion: vmeta.CurrentSchemaVersion,
			Namespace:     "default",
			Path:          canonical,
			Version:       1,
			KeyTerm:       term,
			BackendID:     fb.ID(),
			Algorithm:     string(envelope.AES256GCM),
		},
	}

	plaintext := []byte("aesgcm-roundtrip-test-value")

	if err := fb.SetVersionedEncrypted(ctx, canonical, vm, plaintext, kr); err != nil {
		t.Fatalf("SetVersionedEncrypted (AES-GCM): %v", err)
	}

	got, err := fb.GetVersionedEncrypted(ctx, canonical, vm, kr)
	if err != nil {
		t.Fatalf("GetVersionedEncrypted (AES-GCM): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("AES-GCM round-trip mismatch: got %q, want %q", got, plaintext)
	}

	// On-disk bytes must not be plaintext.
	vp := filepath.Join(dir, "values", "default", "test", "aesgcm_key", "1")
	rawBytes, err := os.ReadFile(vp)
	if err != nil {
		t.Fatalf("ReadFile raw value: %v", err)
	}
	if bytes.Equal(rawBytes, plaintext) {
		t.Error("AES-GCM: raw on-disk bytes equal plaintext — encryption not applied")
	}
}

// TestAESGCM_SetGet_RoundTrip verifies the AES-256-GCM path in the high-level
// Set and Get methods.
func TestAESGCM_SetGet_RoundTrip(t *testing.T) {
	b := openAESGCMKeyringBackend(t)
	defer b.Close()

	path := "default/ai/openrouter/api_key"
	want := []byte("aesgcm-set-get-secret")
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	if err := b.Set(context.Background(), path, want, meta); err != nil {
		t.Fatalf("Set (AES-GCM): %v", err)
	}

	got, gotMeta, err := b.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("Get (AES-GCM): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("AES-GCM Set/Get round-trip mismatch: got %q, want %q", got, want)
	}
	if gotMeta.Path != path {
		t.Errorf("Get meta.Path: got %q, want %q", gotMeta.Path, path)
	}
}

// TestAESGCM_MultipleValues verifies that multiple distinct values can be
// stored and retrieved with AES-256-GCM (exercises GCM nonce counter advancement).
func TestAESGCM_MultipleValues(t *testing.T) {
	b := openAESGCMKeyringBackend(t)
	defer b.Close()

	ctx := context.Background()
	entries := map[string][]byte{
		"default/ai/openrouter/api_key":    []byte("sk-openrouter-aesgcm"),
		"default/ai/anthropic/api_key":     []byte("sk-anthropic-aesgcm"),
		"default/storage/dropbox/token":    []byte("token-dropbox-aesgcm"),
		"default/devtools/github/pat":      []byte("ghp-aesgcm"),
		"default/observability/sentry/dsn": []byte("https://sentry.io/aesgcm"),
	}

	for p, v := range entries {
		meta := backend.Meta{Path: p, Backend: "file", Version: 1}
		if err := b.Set(ctx, p, v, meta); err != nil {
			t.Fatalf("Set %q (AES-GCM): %v", p, err)
		}
	}

	for p, want := range entries {
		got, _, err := b.Get(ctx, p)
		if err != nil {
			t.Fatalf("Get %q (AES-GCM): %v", p, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("AES-GCM Get %q: got %q, want %q", p, got, want)
		}
	}
}

// TestAESGCM_Versioned_RoundTrip verifies SetVersioned/GetVersioned with AES-GCM.
func TestAESGCM_Versioned_RoundTrip(t *testing.T) {
	b := openAESGCMKeyringBackend(t)
	defer b.Close()

	canonical := "default/test/aesgcm-versioned"
	want := []byte("aesgcm-versioned-value")

	if err := b.SetVersioned(context.Background(), canonical, 1, want); err != nil {
		t.Fatalf("SetVersioned (AES-GCM): %v", err)
	}

	got, err := b.GetVersioned(context.Background(), canonical, 1)
	if err != nil {
		t.Fatalf("GetVersioned (AES-GCM): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("AES-GCM versioned round-trip: got %q, want %q", got, want)
	}
}

// TestAESGCM_Delete_RoundTrip verifies Delete works with an AES-GCM backend.
func TestAESGCM_Delete_RoundTrip(t *testing.T) {
	b := openAESGCMKeyringBackend(t)
	defer b.Close()

	path := "default/ai/delete-test/key"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	if err := b.Set(context.Background(), path, []byte("val"), meta); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := b.Delete(context.Background(), path); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, _, err := b.Get(context.Background(), path)
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("Get after Delete (AES-GCM): got %v, want ErrNotFound", err)
	}
}

// TestAESGCM_ManifestPersistence verifies that AES-GCM encrypted values
// persist across backend re-opens.
func TestAESGCM_ManifestPersistence(t *testing.T) {
	dir := t.TempDir()

	b1 := openAESGCMKeyringBackendInDir(t, dir)
	path := "default/persist/aesgcm"
	want := []byte("persistent-aesgcm-value")
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	if err := b1.Set(context.Background(), path, want, meta); err != nil {
		t.Fatalf("Set (AES-GCM): %v", err)
	}
	b1.Close()

	b2 := openAESGCMKeyringBackendInDir(t, dir)
	defer b2.Close()

	got, _, err := b2.Get(context.Background(), path)
	if err != nil {
		t.Fatalf("Get after reopen (AES-GCM): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("AES-GCM persistence mismatch: got %q, want %q", got, want)
	}
}

// TestAESGCM_AADMismatch verifies GetVersionedEncrypted returns ErrAEADAuthFailed
// on path/version/backend_id mismatch with AES-GCM.
func TestAESGCM_AADMismatch(t *testing.T) {
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.AES256GCM)
	defer kr.Zero()

	fb, _ := file.Open(file.Options{Dir: dir})
	defer fb.Close()

	ctx := context.Background()
	canonical := "default/test/aesgcm-aad-mismatch"

	_, term, _ := kr.ActiveDEK()
	vm := vmeta.VersionMeta{
		Version: 1,
		AAD: vmeta.AADBinding{
			SchemaVersion: vmeta.CurrentSchemaVersion,
			Namespace:     "default",
			Path:          canonical,
			Version:       1,
			KeyTerm:       term,
			BackendID:     fb.ID(),
			Algorithm:     string(envelope.AES256GCM),
		},
	}

	plaintext := []byte("aesgcm-aad-mismatch-test")
	if err := fb.SetVersionedEncrypted(ctx, canonical, vm, plaintext, kr); err != nil {
		t.Fatalf("SetVersionedEncrypted: %v", err)
	}

	// Version mismatch.
	vmWrongVersion := vm
	vmWrongVersion.AAD.Version = 999
	_, err := fb.GetVersionedEncrypted(ctx, canonical, vmWrongVersion, kr)
	if !errors.Is(err, envelope.ErrAEADAuthFailed) {
		t.Errorf("AES-GCM AAD version mismatch: got %v, want ErrAEADAuthFailed", err)
	}
}

// TestInitKeyring_AESGCM verifies InitKeyring works with AES-256-GCM algorithm.
func TestInitKeyring_AESGCM(t *testing.T) {
	dir := t.TempDir()

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 7)
	}
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	k, err := kek.PassphraseKEK([]byte("aesgcm-init-pass"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}

	ctx := context.Background()
	if err := file.InitKeyring(ctx, dir, k, envelope.AES256GCM); err != nil {
		t.Fatalf("InitKeyring (AES-GCM): %v", err)
	}

	krPath := filepath.Join(dir, "keyring", "keyring.json")
	if _, err := os.Stat(krPath); err != nil {
		t.Errorf("keyring.json not found after AES-GCM init: %v", err)
	}

	// Should be idempotent.
	k2, _ := kek.PassphraseKEK([]byte("aesgcm-init-pass"), salt, params)
	if err := file.InitKeyring(ctx, dir, k2, envelope.AES256GCM); err != nil {
		t.Errorf("InitKeyring idempotent (AES-GCM): %v", err)
	}
}

// TestAESGCM_GetVersionedEncrypted_MissingCiphertext verifies that
// GetVersionedEncrypted returns ErrNotFound when the value file is absent.
func TestAESGCM_GetVersionedEncrypted_MissingCiphertext(t *testing.T) {
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.AES256GCM)
	defer kr.Zero()

	fb, _ := file.Open(file.Options{Dir: dir})
	defer fb.Close()

	_, term, _ := kr.ActiveDEK()
	vm := vmeta.VersionMeta{
		Version: 1,
		AAD: vmeta.AADBinding{
			Path:      "default/missing/key",
			Version:   1,
			KeyTerm:   term,
			BackendID: fb.ID(),
			Algorithm: string(envelope.AES256GCM),
		},
	}

	_, err := fb.GetVersionedEncrypted(context.Background(), "default/missing/key", vm, kr)
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("GetVersionedEncrypted missing ciphertext: got %v, want ErrNotFound", err)
	}
}
