//go:build !windows

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListenSocket_OwnerOnlyAndNoStagingLeft(t *testing.T) {
	t.Parallel()
	dir := shortTempDir(t)
	path := filepath.Join(dir, "x.sock")

	ln, err := listenSocket(path)
	if err != nil {
		t.Fatalf("listenSocket: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket: %v", path, info.Mode())
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %o, want 600", perm)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected only the socket in %s, found %d entries", dir, len(entries))
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial socket at its final path: %v", err)
	}
	_ = conn.Close()
}

func TestListenSocket_MissingParentDir(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing", "x.sock")
	if ln, err := listenSocket(path); err == nil {
		_ = ln.Close()
		t.Fatal("expected an error when the socket's directory does not exist")
	}
}

func TestListenSocket_PathTakenByDirectory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "x.sock")
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := listenSocket(path)
	if err == nil {
		_ = ln.Close()
		t.Fatal("expected an error when a non-empty directory occupies the socket path")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("staging directory left behind: %d entries", len(entries))
	}
}

func TestListenSocket_RejectsTooLongPath(t *testing.T) {
	t.Parallel()
	dir := shortTempDir(t)
	long := filepath.Join(dir, strings.Repeat("d", maxSocketPath), "x.sock")
	if _, err := listenSocket(long); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected a too-long error, got %v", err)
	}
}
