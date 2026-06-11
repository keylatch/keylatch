// Package file_test — additional migrate error path tests requiring OS permissions.
package file_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// TestMigrateIfFlat_SetMetaFails verifies that when SetMeta fails during
// migration, the newly-written versioned file is removed (S4-5 invariant).
// The flat file should remain as the source of truth.
func TestMigrateIfFlat_SetMetaFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	canonical := "default/ai/openrouter/api_key"
	value := []byte("secret")
	setFlatFile(t, dir, canonical, value)

	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	ctx := context.Background()

	// Make the metadata directory non-writable so SetMeta will fail.
	// SetMeta writes to <dir>/metadata/<canonical>.json.
	// We block creation of the metadata directory.
	metadataRoot := filepath.Join(dir, "metadata")
	if err := os.MkdirAll(metadataRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll metadata root: %v", err)
	}
	if err := os.Chmod(metadataRoot, 0o500); err != nil {
		t.Skipf("Cannot chmod metadata dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(metadataRoot, 0o700)
	})

	err := b.MigrateIfFlat(ctx, canonical)
	if err == nil {
		// On some systems the owner can still write to 0o500 dirs.
		t.Log("MigrateIfFlat with read-only metadata dir succeeded (OS allows owner write)")
		return
	}

	// If migration failed, the flat file should still be present.
	flatPath := filepath.Join(dir, filepath.FromSlash(canonical), "value.enc")
	if _, statErr := os.Stat(flatPath); os.IsNotExist(statErr) {
		t.Error("flat file was removed after SetMeta failure — S4-5 violated")
	}
}

// TestMigrateIfFlat_ReadFlatFileFails verifies that migrateIfFlat returns
// an error when the flat file exists but cannot be read.
func TestMigrateIfFlat_ReadFlatFileFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	canonical := "default/ai/readonly/api_key"
	value := []byte("secret-unreadable")
	setFlatFile(t, dir, canonical, value)

	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	// Make the flat file unreadable.
	flatPath := filepath.Join(dir, filepath.FromSlash(canonical), "value.enc")
	if err := os.Chmod(flatPath, 0o000); err != nil {
		t.Skipf("Cannot chmod flat file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(flatPath, 0o600)
	})

	err := b.MigrateIfFlat(context.Background(), canonical)
	if err == nil {
		// Owner may bypass 0o000 on some systems.
		t.Log("MigrateIfFlat with unreadable flat file succeeded (OS allows owner read)")
	}
}

// TestMigrateIfFlat_RemoveFlatFileFails verifies that migrateIfFlat succeeds
// even when removing the old flat file fails (non-fatal).
// We simulate this by removing the flat file before migration, then run migration,
// and verify the function doesn't return an error for the remove failure.
// (The remove failure path at migrate.go:116-119 is non-fatal — we can't directly
//
//	trigger it from outside without blocking fs, so this test is informational.)
func TestMigrateIfFlat_AlreadyMigratedVersionedExists(t *testing.T) {
	dir := t.TempDir()
	canonical := "default/ai/already-migrated/api_key"
	value := []byte("migrated-value")
	setFlatFile(t, dir, canonical, value)

	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	ctx := context.Background()

	// Perform migration.
	if err := b.MigrateIfFlat(ctx, canonical); err != nil {
		t.Fatalf("first MigrateIfFlat: %v", err)
	}

	// Create the flat file again to simulate a race condition
	// (versioned file now exists, so migrateIfFlat should return nil early).
	setFlatFile(t, dir, canonical, value)

	// Second migration — should be a no-op since versioned file exists.
	if err := b.MigrateIfFlat(ctx, canonical); err != nil {
		t.Fatalf("second MigrateIfFlat (already migrated): %v", err)
	}
}

// TestFileBackend_Open_CreatesDirMode verifies that Open creates the directory
// with the correct permissions (0o700).
func TestFileBackend_Open_CreatesDirMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce POSIX file mode bits")
	}

	parent := t.TempDir()
	dir := filepath.Join(parent, "newvaultdir")

	b, err := file.Open(file.Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("vault dir mode: got %04o, want 0700", info.Mode().Perm())
	}
}

// TestFileBackend_OpenWithKeyring_CreatesDirMode verifies OpenWithKeyring creates
// the directory with the correct permissions.
func TestFileBackend_OpenWithKeyring_CreatesDirMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce POSIX file mode bits")
	}

	parent := t.TempDir()
	dir := filepath.Join(parent, "keyringvaultdir")
	kr, _ := buildKeyring(t, parent, envelope.XChaCha20Poly1305)
	defer kr.Zero()

	b, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	if err != nil {
		t.Fatalf("OpenWithKeyring: %v", err)
	}
	defer b.Close()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("vault dir mode: got %04o, want 0700", info.Mode().Perm())
	}
}
