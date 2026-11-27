//go:build !unix

package brokerd

import (
	"errors"
	"net"
	"os"
)

func receiveFiles(*net.UnixConn, int) ([]*os.File, error) {
	return nil, errors.New("file descriptor passing is not available on this platform")
}
