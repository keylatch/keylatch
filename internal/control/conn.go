package control

import "net"

// Conn is a connected, full-duplex stream between the daemon and a client. It
// is a Unix socket everywhere except the Windows broker, whose clients connect
// over a named pipe. CloseWrite ends the stream the peer reads; a transport
// without a half-close ends the whole connection instead.
type Conn interface {
	net.Conn
	CloseWrite() error
}
