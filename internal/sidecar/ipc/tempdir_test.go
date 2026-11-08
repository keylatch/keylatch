package ipc

import (
	"os"
	"runtime"
	"testing"
)

// Socket paths must fit sun_path even when test names or macOS TMPDIR are long.
func shortTempDir(t *testing.T) string {
	t.Helper()
	base := "/tmp"
	if runtime.GOOS == "windows" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "kl")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
