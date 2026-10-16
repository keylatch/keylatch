//go:build !unix

package childstore

import (
	"errors"
	"net"
	"os"
)

// Pair is unavailable: the broker's children run on Unix.
func Pair() (net.Conn, *os.File, error) {
	return nil, nil, errors.New("childstore: not supported on this platform")
}
