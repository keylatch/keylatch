//go:build windows

package winpipe

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procClientSessionID = kernel32.NewProc("GetNamedPipeClientSessionId")
	procWaitNamedPipe   = kernel32.NewProc("WaitNamedPipeW")
	errClosed           = net.ErrClosed
)

const (
	pipeBufferSize = 64 << 10
	flushTimeout   = 5 * time.Second
)

// Conn is one end of a named pipe. Reads and writes use overlapped I/O, so a
// blocked read does not hold up a write on the same handle, and deadlines and
// Close cancel a pending operation.
type Conn struct {
	h windows.Handle
	// mu is held shared by every operation and exclusively by Close, which
	// closes the handle only after the operations have left.
	mu     sync.RWMutex
	closed atomic.Bool

	rmu, wmu      sync.Mutex
	rev, wev      windows.Handle // completion events
	rwake, wwake  windows.Handle // set when a deadline changes or the conn closes
	rdl, wdl      atomic.Int64   // deadlines as unix nanoseconds, 0 for none
	local, remote addr
}

type addr string

func (addr) Network() string  { return "pipe" }
func (a addr) String() string { return string(a) }

func newConn(h windows.Handle, name string) (*Conn, error) {
	c := &Conn{h: h, local: addr(name), remote: addr(name)}
	var err error
	for _, p := range []*windows.Handle{&c.rev, &c.wev, &c.rwake, &c.wwake} {
		if *p, err = windows.CreateEvent(nil, 1, 0, nil); err != nil {
			c.releaseEvents()
			_ = windows.CloseHandle(h)
			return nil, err
		}
	}
	return c, nil
}

func (c *Conn) releaseEvents() {
	for _, e := range []windows.Handle{c.rev, c.wev, c.rwake, c.wwake} {
		if e != 0 {
			_ = windows.CloseHandle(e)
		}
	}
}

// ClientProcess returns the process id and logon session of the client of a
// server-side connection.
func (c *Conn) ClientProcess() (pid, session uint32, err error) {
	if err := windows.GetNamedPipeClientProcessId(c.h, &pid); err != nil {
		return 0, 0, err
	}
	r, _, e := procClientSessionID.Call(uintptr(c.h), uintptr(unsafe.Pointer(&session)))
	if r == 0 {
		return 0, 0, e
	}
	return pid, session, nil
}

// ServerProcess returns the process id of the server of a client-side connection.
func (c *Conn) ServerProcess() (uint32, error) {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(c.h, &pid); err != nil {
		return 0, err
	}
	return pid, nil
}

func (c *Conn) io(read bool, b []byte) (int, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed.Load() {
		return 0, errClosed
	}
	mu, ev, wake, dl := &c.wmu, c.wev, c.wwake, &c.wdl
	if read {
		mu, ev, wake, dl = &c.rmu, c.rev, c.rwake, &c.rdl
	}
	mu.Lock()
	defer mu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if d := dl.Load(); d != 0 && time.Now().UnixNano() >= d {
		return 0, os.ErrDeadlineExceeded
	}
	_ = windows.ResetEvent(ev)
	_ = windows.ResetEvent(wake)
	ov := windows.Overlapped{HEvent: ev}
	var n uint32
	var err error
	if read {
		err = windows.ReadFile(c.h, b, &n, &ov)
	} else {
		err = windows.WriteFile(c.h, b, &n, &ov)
	}
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		n, err = c.wait(&ov, ev, wake, dl)
	}
	return int(n), mapErr(err, read)
}

// wait blocks until the operation completes, the deadline passes, or Close
// cancels it.
func (c *Conn) wait(ov *windows.Overlapped, ev, wake windows.Handle, dl *atomic.Int64) (uint32, error) {
	for {
		timeout := uint32(windows.INFINITE)
		if d := dl.Load(); d != 0 {
			left := time.Until(time.Unix(0, d))
			if left <= 0 {
				return c.cancel(ov, os.ErrDeadlineExceeded)
			}
			timeout = uint32(min(left.Milliseconds()+1, int64(windows.INFINITE-1)))
		}
		which, err := windows.WaitForMultipleObjects([]windows.Handle{ev, wake}, false, timeout)
		if err != nil {
			return c.cancel(ov, err)
		}
		switch which {
		case windows.WAIT_OBJECT_0:
			var n uint32
			err := windows.GetOverlappedResult(c.h, ov, &n, false)
			return n, err
		case windows.WAIT_OBJECT_0 + 1:
			if c.closed.Load() {
				return c.cancel(ov, errClosed)
			}
			_ = windows.ResetEvent(wake)
		}
		// A timeout loops back to the deadline check.
	}
}

// cancel aborts the pending operation and reports how much of it completed.
func (c *Conn) cancel(ov *windows.Overlapped, reason error) (uint32, error) {
	_ = windows.CancelIoEx(c.h, ov)
	var n uint32
	_ = windows.GetOverlappedResult(c.h, ov, &n, true)
	return n, reason
}

func mapErr(err error, read bool) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_BROKEN_PIPE), errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED), errors.Is(err, windows.ERROR_NO_DATA):
		if read {
			return io.EOF
		}
		return io.ErrClosedPipe
	case errors.Is(err, windows.ERROR_OPERATION_ABORTED):
		return errClosed
	}
	return err
}

// Read implements net.Conn.
func (c *Conn) Read(b []byte) (int, error) { return c.io(true, b) }

// Write implements net.Conn. It writes all of b or returns an error.
func (c *Conn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n, err := c.io(false, b)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		b = b[n:]
	}
	return total, nil
}

// Close implements net.Conn.
func (c *Conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	_ = windows.CancelIoEx(c.h, nil)
	_ = windows.SetEvent(c.rwake)
	_ = windows.SetEvent(c.wwake)
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = windows.DisconnectNamedPipe(c.h)
	err := windows.CloseHandle(c.h)
	c.releaseEvents()
	return err
}

// CloseWrite ends the stream. A pipe has no half-close, so this lets the peer
// read what was written, then closes the whole connection.
func (c *Conn) CloseWrite() error {
	flushed := make(chan struct{})
	go func() {
		defer close(flushed)
		c.mu.RLock()
		defer c.mu.RUnlock()
		if !c.closed.Load() {
			_ = windows.FlushFileBuffers(c.h)
		}
	}()
	select {
	case <-flushed:
	case <-time.After(flushTimeout):
	}
	return c.Close()
}

// LocalAddr implements net.Conn.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr implements net.Conn.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline implements net.Conn.
func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func deadlineValue(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// SetReadDeadline implements net.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.rdl.Store(deadlineValue(t))
	c.poke(c.rwake)
	return nil
}

// SetWriteDeadline implements net.Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.wdl.Store(deadlineValue(t))
	c.poke(c.wwake)
	return nil
}

// poke wakes a pending operation so it re-reads its deadline.
func (c *Conn) poke(wake windows.Handle) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.closed.Load() {
		_ = windows.SetEvent(wake)
	}
}

// Listener accepts clients on a named pipe.
type Listener struct {
	name string
	sa   *windows.SecurityAttributes
	sd   *windows.SECURITY_DESCRIPTOR

	mu     sync.Mutex
	next   windows.Handle // the instance waiting for the next client
	first  bool
	closed bool
	stop   windows.Handle
}

// Listen creates the pipe at name (\\.\pipe\...) with the security descriptor
// sddl. The first instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE, so
// the call fails when another process already owns the name.
func Listen(name, sddl string) (*Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		name:  name,
		sd:    sd,
		sa:    &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd},
		first: true,
	}
	if l.stop, err = windows.CreateEvent(nil, 1, 0, nil); err != nil {
		return nil, err
	}
	if l.next, err = l.instance(); err != nil {
		_ = windows.CloseHandle(l.stop)
		return nil, err
	}
	return l, nil
}

func (l *Listener) instance() (windows.Handle, error) {
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if l.first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	p, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateNamedPipe(p, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, pipeBufferSize, pipeBufferSize, 0, l.sa)
	if err != nil {
		return 0, err
	}
	l.first = false
	return h, nil
}

// Accept waits for the next client.
func (l *Listener) Accept() (*Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, errClosed
	}
	h := l.next
	// The replacement exists before this client is served, so there is never a
	// moment without an instance for the next client to find.
	next, err := l.instance()
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	l.next = next
	l.mu.Unlock()

	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	ov := windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, &ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
	case errors.Is(err, windows.ERROR_IO_PENDING):
		which, werr := windows.WaitForMultipleObjects([]windows.Handle{ev, l.stop}, false, windows.INFINITE)
		if werr != nil || which != windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(h, &ov)
			var n uint32
			_ = windows.GetOverlappedResult(h, &ov, &n, true)
			_ = windows.CloseHandle(h)
			if werr != nil {
				return nil, werr
			}
			return nil, errClosed
		}
		var n uint32
		if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil {
			_ = windows.CloseHandle(h)
			return nil, err
		}
	default:
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return newConn(h, l.name)
}

// Close stops the listener. Connections already accepted stay open.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	_ = windows.SetEvent(l.stop)
	err := windows.CloseHandle(l.next)
	return err
}

// Dial connects to the pipe at name, waiting up to timeout for a free instance.
// The connection allows the server to identify the client but not to
// impersonate it.
func Dial(name string, timeout time.Duration) (*Conn, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			return newConn(h, name)
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			return nil, err
		}
		wait := max(time.Until(deadline).Milliseconds(), 1)
		_, _, _ = procWaitNamedPipe.Call(uintptr(unsafe.Pointer(p)), uintptr(min(wait, 250)))
	}
}

// Exists reports whether a pipe of that name has been created.
func Exists(name string) bool {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	r, _, e := procWaitNamedPipe.Call(uintptr(unsafe.Pointer(p)), 1)
	return r != 0 || errors.Is(e, windows.ERROR_SEM_TIMEOUT)
}
