//go:build !linux && !darwin

package control

import (
	"errors"
	"net"
)

func peerOf(*net.UnixConn) (Peer, error) {
	return Peer{}, errors.New("control: peer credentials are not available on this platform")
}
