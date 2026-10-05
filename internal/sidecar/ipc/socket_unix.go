//go:build !windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// listenSocket creates a Unix domain socket at path with mode 0600.
//
// The socket is bound inside a fresh 0700 directory next to path, narrowed
// to 0600 and then renamed into place, so it is never reachable by other
// users even briefly. Changing the umask instead would affect every
// goroutine in the process that creates a file at the same time.
func listenSocket(path string) (net.Listener, error) {
	dir, err := os.MkdirTemp(filepath.Dir(path), ".ipc-")
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
