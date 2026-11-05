package contained

import (
	"io"
	"net"
	"sync"
	"time"
)

// Forward accepts connections on l and pipes each one to a fresh connection
// from dial until l is closed. It is the namespace's only way out: the child
// connects to the loopback listener and the bytes reach the daemon's egress
// proxy.
func Forward(l net.Listener, dial func() (net.Conn, error)) {
	for {
		in, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			out, err := dial()
			if err != nil {
				_ = in.Close()
				return
			}
			pipe(in, out)
		}()
	}
}

// pipe copies both ways and returns once both directions have ended.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	half := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now())
		}
	}
	go half(a, b)
	go half(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
