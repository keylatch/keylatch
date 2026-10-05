package ipc

import (
	"os"
	"runtime"
	"testing"
)

// shortTempDir returns a temp dir with a short path: macOS's default TMPDIR is
// long enough to push socket paths past the sun_path limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("/tmp", "kl")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
