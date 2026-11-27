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
	// SOCK_CLOEXEC does not exist on every Unix; the lock keeps a concurrent
	// fork from inheriting the descriptors before they are marked.
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("childstore: %w", err)
	}
	parent := os.NewFile(uintptr(fds[0]), "childstore-broker")
	child := os.NewFile(uintptr(fds[1]), "childstore-child")
	defer func() { _ = parent.Close() }()
	conn, err := net.FileConn(parent)
	if err != nil {
		_ = child.Close()
		return nil, nil, fmt.Errorf("childstore: %w", err)
	}
	return conn, child, nil
}

// markCloseOnExec keeps a descriptor out of any program this process starts.
func markCloseOnExec(fd int) { syscall.CloseOnExec(fd) }
