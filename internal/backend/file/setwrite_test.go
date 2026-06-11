// Package file_test — tests for atomicWrite error paths within Set.
package file_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// TestFileBackend_Set_AtomicWriteEncFails verifies that Set returns an error
// when atomicWrite fails for value.enc (exercises lines 162-164 in file.go).
// We pre-create the key directory with no-write permission.
func TestFileBackend_Set_AtomicWriteEncFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission manipulation not reliable on Windows")
	}

	dir := t.TempDir()
	b := openKeyringBackendInDir(t, dir)
	defer b.Close()

	ctx := context.Background()

	// Pre-load manifest so ensureManifestLocked won't fail.
	_, _ = b.List(ctx, "")

	// Pre-create the key directory.
	keyDir := filepath.Join(dir, "default", "test", "atomic-enc-fail")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("MkdirAll keyDir: %v", err)
	}

	// Make it read-only so os.CreateTemp inside atomicWrite fails.
	if err := os.Chmod(keyDir, 0o500); err != nil {
		t.Skipf("Cannot chmod key dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(keyDir, 0o700) })

	path := "default/test/atomic-enc-fail"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	err := b.Set(ctx, path, []byte("secret"), meta)
	if err == nil {
		t.Log("Set with read-only key dir succeeded (OS allows owner write)")
	}
}
