//go:build windows

package ipc

import (
	"fmt"
	"net"
)

// listenSocket on Windows. Unix domain sockets on Windows (10 1809+) do not
// support umask-based permission control; Windows uses ACLs instead.
// The Tauri desktop shell (keylatchd) is not shipped for Windows in the
// current release, so this path is compile-only.
func listenSocket(path string) (net.Listener, error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix: %w", err)
	}
	return ln, nil
}
