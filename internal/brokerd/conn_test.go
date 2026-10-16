package brokerd

import "net"

// pipeConn is an in-memory control.Conn; it has no half-close, like a named pipe.
type pipeConn struct{ net.Conn }

func (p pipeConn) CloseWrite() error { return p.Close() }

func connPair() (server, client pipeConn) {
	a, b := net.Pipe()
	return pipeConn{a}, pipeConn{b}
}
