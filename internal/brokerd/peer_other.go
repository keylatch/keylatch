//go:build !linux

package brokerd

import "net"

// Identify is unavailable off Linux: the system broker is Linux-only.
func Identify(*net.UnixConn) (*Identity, error) { return nil, ErrUnsupported }
