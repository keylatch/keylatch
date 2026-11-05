//go:build !linux && !darwin

package socketrelay

import (
	"errors"
	"net"
)

func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are not available on this platform")
}
