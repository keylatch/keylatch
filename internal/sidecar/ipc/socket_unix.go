//go:build !windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// listenSocket creates a Unix domain socket at path with mode 0600.
// M7: a restrictive umask is applied before net.Listen so the socket file
// is never world-accessible even briefly.
func listenSocket(path string) (net.Listener, error) {
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	// Chmod is redundant after the umask but kept for defense-in-depth.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return ln, nil
}
