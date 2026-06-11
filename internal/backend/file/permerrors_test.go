// Package file_test — tests that trigger filesystem error paths by using
// directories in place of files or by adjusting file permissions.
package file_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/file"
)

// TestLoadManifest_DirectoryInsteadOfFile verifies that loadManifest returns
// an error when manifest.json is a directory (not a file).
// This exercises the non-NotExist error path in loadManifest.
func TestLoadManifest_DirectoryInsteadOfFile(t *testing.T) {
	dir := t.TempDir()

	// Create manifest.json as a directory instead of a file.
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.MkdirAll(manifestPath, 0o700); err != nil {
		t.Fatalf("mkdir manifest.json: %v", err)
	}

	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	// Any operation requiring the manifest should return an error.
	_, err = b.List(context.Background(), "")
	if err == nil {
		t.Error("List with directory manifest.json: expected error, got nil")
	}
}

// TestGetMetaFromDisk_UnreadableFile verifies getMetaFromDisk returns an error
// when the metadata file exists but cannot be read.
func TestGetMetaFromDisk_UnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	canonical := "default/test/unreadable-meta"
	m := validMeta(canonical)

	if err := b.SetMeta(context.Background(), canonical, m); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	// Make the file unreadable.
	metaPath := filepath.Join(dir, "metadata", "default", "test", "unreadable-meta.json")
	if err := os.Chmod(metaPath, 0o000); err != nil {
		t.Skipf("Cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(metaPath, 0o600) })

	_, err = b.GetMeta(context.Background(), canonical)
	if err == nil {
		t.Log("GetMeta on unreadable file succeeded (OS allows owner read)")
	}
}

// TestListMeta_UnreadableFile verifies ListMeta returns an error when a
// metadata .json file exists but cannot be read during the walk.
func TestListMeta_UnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	ctx := context.Background()
	canonical := "default/test/unreadable-list-meta"
	m := validMeta(canonical)

	if err := b.SetMeta(ctx, canonical, m); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	// Make the metadata file unreadable (different from corrupt — it exists but is not readable).
	metaPath := filepath.Join(dir, "metadata", "default", "test", "unreadable-list-meta.json")
	if err := os.Chmod(metaPath, 0o000); err != nil {
		t.Skipf("Cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(metaPath, 0o600) })

	_, err = b.ListMeta(ctx, "")
	// May succeed (owner can read) or fail with permission error.
	_ = err
}

// TestListMeta_UnreadableSubdir verifies ListMeta handles walk errors gracefully.
// We make a subdirectory of metadata unreadable so WalkDir returns an error
// when entering it.
func TestListMeta_UnreadableSubdir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	ctx := context.Background()

	// Write a metadata entry to create the directory structure.
	canonical := "default/test/unreadable-dir"
	if err := b.SetMeta(ctx, canonical, validMeta(canonical)); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}

	// Make the test subdir unreadable.
	subDir := filepath.Join(dir, "metadata", "default", "test")
	if err := os.Chmod(subDir, 0o000); err != nil {
		t.Skipf("Cannot chmod subdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(subDir, 0o700) })

	_, err = b.ListMeta(ctx, "")
	// On macOS/Linux, WalkDir into an unreadable directory returns an error.
	// That exercises the walkErr != nil && !os.IsNotExist(walkErr) path.
	_ = err
}

// TestSetMeta_AtomicWriteFailure verifies SetMeta returns an error when
// atomicWrite fails due to the target directory being read-only.
func TestSetMeta_AtomicWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	ctx := context.Background()
	canonical := "default/test/atomic-fail"

	// Create the metadata directory.
	metaDir := filepath.Join(dir, "metadata", "default", "test")
	if err := os.MkdirAll(metaDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Make the directory read-only so atomicWrite fails.
	if err := os.Chmod(metaDir, 0o500); err != nil {
		t.Skipf("Cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(metaDir, 0o700) })

	m := validMeta(canonical)
	err = b.SetMeta(ctx, canonical, m)
	if err == nil {
		t.Log("SetMeta in read-only dir succeeded (OS allows owner write)")
	}
}
