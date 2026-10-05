//go:build !windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// maxSocketPath is the shortest sun_path limit across supported Unix
// platforms (104 bytes on macOS and the BSDs, 108 on Linux), minus the
// terminating NUL.
const maxSocketPath = 103

// listenSocket creates a Unix domain socket at path with mode 0600.
//
// The socket is bound inside a fresh 0700 directory next to path, narrowed
// to 0600 and then renamed into place, so it is never reachable by other
// users even briefly. Changing the umask instead would affect every
// goroutine in the process that creates a file at the same time.
func listenSocket(path string) (net.Listener, error) {
	// MkdirTemp appends at most 10 random digits to the pattern.
	if n := len(filepath.Join(filepath.Dir(path), ".s0123456789", "s")); n > maxSocketPath {
		return nil, fmt.Errorf("socket path %s is too long for a Unix socket (%d bytes staged, limit %d): choose a shorter path", path, n, maxSocketPath)
	}
	dir, err := os.MkdirTemp(filepath.Dir(path), ".s")
	if err != nil {
		return nil, fmt.Errorf("create socket staging dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	staged := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", staged)
	if err != nil {
		return nil, err
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Chmod(staged, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	if err := os.Rename(staged, path); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("move socket into place: %w", err)
	}
	return ln, nil
}
