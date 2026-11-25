package proxy

import (
	"net"
	"sync"
)

// oneConnListener hands one connection to an http.Server and reports closed
// once that connection is, so Serve returns when the tunnel ends.
type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
	used   bool
	mu     sync.Mutex
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, closed: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return &notifyConn{Conn: l.conn, onClose: l.finish}, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) finish() { l.once.Do(func() { close(l.closed) }) }

func (l *oneConnListener) Close() error { l.finish(); return nil }

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyConn struct {
	net.Conn
	onClose func()
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.onClose()
	return err
}
