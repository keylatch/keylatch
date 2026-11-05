package brokerd

import (
	"net"
	"os"
)

func writeFileForTest(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }

// pipeConn is an in-memory control.Conn; it has no half-close, like a named pipe.
type pipeConn struct{ net.Conn }

func (p pipeConn) CloseWrite() error { return p.Close() }

func connPair() (server, client pipeConn) {
	a, b := net.Pipe()
	return pipeConn{a}, pipeConn{b}
}
