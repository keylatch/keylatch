//go:build !linux && !darwin

package control

import (
	"errors"
	"net"
)

// Peer is the kernel-attested identity of the process on the other end of a
// Unix socket.
type Peer struct {
	UID uint32
	PID int
}

func peerOf(*net.UnixConn) (Peer, error) {
	return Peer{}, errors.New("control: peer credentials are not available on this platform")
}
