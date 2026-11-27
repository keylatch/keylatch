//go:build !unix

package childstore

import (
	"errors"
	"net"
	"os"
)

// Pair is unavailable: the daemon hands its store to a served verb through an
// inherited descriptor, which a Windows child cannot receive.
func Pair() (net.Conn, *os.File, error) {
	return nil, nil, errors.New("the broker cannot give a served command its store on this platform; use 'keylatch run' instead")
}

func markCloseOnExec(int) {}
