//go:build !windows

package winpipe

import (
	"net"
	"time"
)

// Conn is a stub that never exists off Windows.
type Conn struct{ net.Conn }

// CloseWrite is part of the connection contract.
func (*Conn) CloseWrite() error { return ErrUnsupported }

// ClientProcess is part of the connection contract.
func (*Conn) ClientProcess() (pid, session uint32, err error) { return 0, 0, ErrUnsupported }

// ServerProcess is part of the connection contract.
func (*Conn) ServerProcess() (uint32, error) { return 0, ErrUnsupported }

// Listener is a stub that never exists off Windows.
type Listener struct{}

// Listen reports ErrUnsupported.
func Listen(string, string) (*Listener, error) { return nil, ErrUnsupported }

// Accept reports ErrUnsupported.
func (*Listener) Accept() (*Conn, error) { return nil, ErrUnsupported }

// Close does nothing.
func (*Listener) Close() error { return nil }

// Dial reports ErrUnsupported.
func Dial(string, time.Duration) (*Conn, error) { return nil, ErrUnsupported }

// Exists reports false: there is no pipe to find.
func Exists(string) bool { return false }
