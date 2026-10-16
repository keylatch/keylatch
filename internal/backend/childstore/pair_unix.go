//go:build unix

package childstore

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// Pair returns the broker's connection and the file to pass the child as its
// first extra descriptor.
func Pair() (net.Conn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("childstore: %w", err)
	}
	parent := os.NewFile(uintptr(fds[0]), "childstore-broker")
	child := os.NewFile(uintptr(fds[1]), "childstore-child")
	defer parent.Close()
	conn, err := net.FileConn(parent)
	if err != nil {
		child.Close()
		return nil, nil, fmt.Errorf("childstore: %w", err)
	}
	return conn, child, nil
}
