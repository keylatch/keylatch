package control

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// LocalEnv set to 1 makes the CLI act on local state instead of asking the
// daemon. The daemon sets it for the verbs it runs on a caller's behalf.
const LocalEnv = "KEYLATCH_LOCAL"

const maxResponse = 32 << 20

// ErrNoDaemon is returned when no daemon answers on the control socket.
var ErrNoDaemon = errors.New("control: no daemon on the control socket")

// Client talks to the daemon over the control socket. It holds no key material.
type Client struct {
	socket  string
	signals []string
	ticket  string
}

// NewClient returns a Client for the socket the lookup selects, or ErrNoDaemon
// when nothing answers there.
func NewClient(lookup llmcontext.Lookup) (*Client, error) {
	c := &Client{
		socket:  paths.ControlSocket(lookup),
		signals: llmcontext.Classify(lookup).Signals,
		ticket:  lookup(llmcontext.TicketEnv),
	}
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	_ = conn.Close()
	return c, nil
}

// dial connects and checks that the listener runs as this user, so a socket
// planted by another account is never trusted.
func (c *Client) dial() (*net.UnixConn, error) {
	conn, err := net.DialTimeout("unix", c.socket, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDaemon, err)
	}
	uc := conn.(*net.UnixConn)
	peer, err := peerOf(uc)
	if err != nil || (peer.UID != uint32(os.Getuid()) && peer.UID != 0) { //nolint:gosec // G115: uid is non-negative
		_ = conn.Close()
		return nil, errors.New("control: refusing a socket owned by another user")
	}
	return uc, nil
}

func (c *Client) stamp(req Request) Request {
	req.Signals, req.Ticket = c.signals, c.ticket
	return req
}

func (c *Client) roundTrip(req Request) (Response, error) {
	conn, err := c.dial()
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := writeFrame(conn, c.stamp(req)); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := readFrame(bufio.NewReader(conn), &resp, maxResponse); err != nil {
		return Response{}, err
	}
	return resp, nil
}

// Exec asks the daemon to run a served verb.
func (c *Client) Exec(global []string, verb string, args []string) (Response, error) {
	return c.roundTrip(Request{Op: OpExec, Global: global, Verb: verb, Args: args})
}

// RunSession asks the daemon for a scoped session.
func (c *Client) RunSession(rr RunRequest) (Response, error) {
	return c.roundTrip(Request{Op: OpRunSession, Run: &rr})
}

// Key asks the daemon to perform a key operation.
func (c *Client) Key(kr KeyRequest) (Response, error) {
	return c.roundTrip(Request{Op: OpKey, Key: &kr})
}

// KeyPolicy lists or edits the key operation allowlist.
func (c *Client) KeyPolicy(kp KeyPolicyRequest) (Response, error) {
	return c.roundTrip(Request{Op: OpKeyPolicy, KeyPolicy: &kp})
}

// Forward listens on a loopback port in the caller's own network namespace and
// relays each connection to the gateway through the daemon. The returned
// address is where a sandboxed child reaches the gateway.
func (c *Client) Forward() (addr string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("control: forwarder: %w", err)
	}
	var (
		mu     sync.Mutex
		open   = map[net.Conn]struct{}{}
		closed bool
		wg     sync.WaitGroup
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			open[conn] = struct{}{}
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() {
					mu.Lock()
					delete(open, conn)
					mu.Unlock()
					_ = conn.Close()
				}()
				c.relay(conn)
			}()
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		mu.Lock()
		closed = true
		for conn := range open {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	}, nil
}

func (c *Client) relay(local net.Conn) {
	up, err := c.dial()
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	if err := writeFrame(up, c.stamp(Request{Op: OpGateway})); err != nil {
		return
	}
	r := bufio.NewReader(up)
	var ack Response
	if err := readFrame(r, &ack, maxFrame); err != nil || !ack.OK {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, local)
		_ = up.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(local, r)
		if tc, ok := local.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
