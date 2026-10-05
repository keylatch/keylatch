//go:build !windows

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenSocket_OwnerOnlyAndNoStagingLeft(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
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
