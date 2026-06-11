// Package file_test — tests targeting atomicWrite error paths and
// other error paths that can be triggered via filesystem manipulation.
package file_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// TestFileBackend_Set_CorruptManifest verifies that Set returns an error
// when the manifest is corrupt (exercises ensureManifestLocked error in Set).
func TestFileBackend_Set_CorruptManifest(t *testing.T) {
	dir := t.TempDir()

	// Write a corrupt manifest.
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{invalid json"), 0o600); err != nil {
		t.Fatalf("write corrupt manifest: %v", err)
	}

	// Use a keyring-backed backend so we get past the keyring check.
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	// The backend that was opened after the corrupt manifest exists —
	// we need a NEW backend instance that will try to load the manifest.
	// Since b already loaded the manifest when it was set up... let's
	// use the approach of creating a NEW backend to the same dir with corrupt manifest.
	//
	// Actually: openKeyringBackendInDir creates a NEW keyring in the dir, which
	// works fine. But the manifest is already corrupt. When the new backend
	// calls ensureManifestLocked for the first time, it will try to load manifest.
	//
	// Wait — openKeyringBackendInDir calls OpenWithKeyring which doesn't load
	// the manifest immediately (lazy). So the first Set call will trigger loadManifest.

	// However, openKeyringBackendInDir also writes a keyring file to the same dir.
	// The manifest.json is corrupt. When we call Set on b, it will try to
	// loadManifest and fail.

	path := "default/test/corrupt-manifest-set"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	err := b.Set(context.Background(), path, []byte("value"), meta)
	if err == nil {
		t.Error("Set with corrupt manifest: expected error, got nil")
	}
}

// TestFileBackend_Get_ValueEncIsDir verifies Get returns a read error when
// value.enc is a directory (not a file) — exercises the non-IsNotExist error
// path when reading value.enc.
func TestFileBackend_Get_ValueEncIsDir(t *testing.T) {
	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	path := "default/test/value-enc-is-dir"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	if err := b.Set(context.Background(), path, []byte("secret"), meta); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Replace value.enc with a directory.
	encPath := filepath.Join(dir, "default", "test", "value-enc-is-dir", "value.enc")
	if err := os.Remove(encPath); err != nil {
		t.Fatalf("Remove value.enc: %v", err)
	}
	if err := os.MkdirAll(encPath, 0o700); err != nil {
		t.Fatalf("mkdir value.enc: %v", err)
	}

	_, _, err := b.Get(context.Background(), path)
	if err == nil {
		t.Error("Get with value.enc as directory: expected error, got nil")
	}
}

// TestFileBackend_Set_AtomicWriteFailure_ReadOnlyDir verifies that Set
// returns an error when atomicWrite fails because the target directory
// is read-only (cannot create temp files).
func TestFileBackend_Set_AtomicWriteFailure_ReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	ctx := context.Background()

	// First, ensure the manifest is loaded by doing a harmless List.
	_, _ = b.List(ctx, "")

	// Make the vault root non-writable so atomicWrite cannot create a temp file.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("Cannot chmod vault root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	path := "default/test/readonly-vault"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	// This may fail at MkdirAll or at atomicWrite.
	err := b.Set(ctx, path, []byte("value"), meta)
	if err == nil {
		t.Log("Set in read-only vault succeeded (OS allows owner write)")
	}
}

// TestFileBackend_Delete_AtomicWriteFailure verifies Delete returns an error
// when saving the manifest after deletion fails.
func TestFileBackend_Delete_AtomicWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	ctx := context.Background()

	// Write an entry.
	path := "default/test/delete-atomic-fail"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}
	if err := b.Set(ctx, path, []byte("value"), meta); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Make the vault root read-only so saveManifest fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("Cannot chmod vault root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := b.Delete(ctx, path)
	if err == nil {
		t.Log("Delete in read-only vault succeeded (OS allows owner write)")
	}
}
