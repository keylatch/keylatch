package control

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// LocalEnv set to 1 makes the CLI act on local state instead of asking the
// daemon. The daemon sets it for the verbs it runs on a caller's behalf.
const LocalEnv = "KEYLATCH_LOCAL"

const maxResponse = 32 << 20

// ErrNoDaemon is returned when no daemon answers on the control socket.
var ErrNoDaemon = errors.New("control: no daemon on the control socket")

// ErrBrokerUnreachable is returned when the system broker's socket exists but
// no daemon answers on it. The client does not fall back to local key files:
// with a broker installed they are not where the keys are.
var ErrBrokerUnreachable = errors.New("control: the system broker socket exists but the daemon does not answer; start it with 'sudo systemctl start keylatchd.socket'")

// lookupBrokerUID resolves the account the system broker runs under. Tests
// replace it.
var lookupBrokerUID = func() (uint32, error) {
	u, err := user.Lookup(paths.BrokerUser)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(uid), err
}

// Client talks to the daemon over the control socket. It holds no key material.
type Client struct {
	socket  string
	broker  bool
	signals []string
	ticket  string
	runID   string
}

// NewClient returns a Client for the socket the lookup selects, or ErrNoDaemon
// when nothing answers there. The system broker's socket is preferred when it
// exists and KEYLATCH_SOCKET does not name another.
func NewClient(lookup llmcontext.Lookup) (*Client, error) {
	return newClient(lookup, llmcontext.Classify(lookup).Signals, lookup(llmcontext.TicketEnv))
}

// NewRawClient is NewClient for a caller that sends no agent signals and no
// ticket of its own. A session ticket verifier uses it: classifying the
// environment to fill in the signals would call the verifier again.
func NewRawClient(lookup llmcontext.Lookup) (*Client, error) {
	return newClient(lookup, nil, "")
}

func newClient(lookup llmcontext.Lookup, signals []string, ticket string) (*Client, error) {
	c := &Client{
		socket:  paths.ControlSocket(lookup),
		signals: signals,
		ticket:  ticket,
	}
	if lookup("KEYLATCH_SOCKET") == "" {
		if sock := paths.BrokerSocket(lookup); isSocket(sock) {
			c.socket, c.broker = sock, true
		}
	}
	conn, err := c.dial()
	if err != nil {
		if c.broker && errors.Is(err, ErrNoDaemon) {
			return nil, ErrBrokerUnreachable
		}
		return nil, err
	}
	_ = conn.Close()
	return c, nil
}

// BrokerInstalled reports whether the system broker's socket exists and
// KEYLATCH_SOCKET does not name another.
func BrokerInstalled(lookup llmcontext.Lookup) bool {
	return lookup("KEYLATCH_SOCKET") == "" && isSocket(paths.BrokerSocket(lookup))
}

func isSocket(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

// Broker reports that the client talks to the system broker.
func (c *Client) Broker() bool { return c.broker }

// trusted reports whether a listener running as uid may be spoken to: this
// user, root (the credentials of a socket-activated listener are the service
// manager's), or, for the system broker, its own account.
func (c *Client) trusted(uid uint32) bool {
	if uid == uint32(os.Getuid()) || uid == 0 { //nolint:gosec // G115: uid is non-negative
		return true
	}
	if !c.broker {
		return false
	}
	broker, err := lookupBrokerUID()
	return err == nil && uid == broker
}

// dial connects and checks who runs the listener, so a socket planted by
// another account is never trusted.
func (c *Client) dial() (*net.UnixConn, error) {
	conn, err := net.DialTimeout("unix", c.socket, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDaemon, err)
	}
	uc := conn.(*net.UnixConn)
	peer, err := peerOf(uc)
	if err != nil || !c.trusted(peer.UID) {
		_ = conn.Close()
		return nil, errors.New("control: refusing a socket owned by another user")
	}
	return uc, nil
}

// Call sends one broker request and returns the daemon's reply. The client's
// agent signals and ticket ride along; they can only make the daemon stricter.
func (c *Client) Call(req brokerapi.Request) (brokerapi.Response, error) {
	if req.Signals == nil {
		req.Signals = c.signals
	}
	if req.Ticket == "" {
		req.Ticket = c.ticket
	}
	conn, err := c.dial()
	if err != nil {
		return brokerapi.Response{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := writeFrame(conn, req); err != nil {
		return brokerapi.Response{}, err
	}
	var resp brokerapi.Response
	if err := readFrame(bufio.NewReader(conn), &resp, maxResponse); err != nil {
		return brokerapi.Response{}, err
	}
	return resp, nil
}

func (c *Client) stamp(req Request) Request {
	req.Signals, req.Ticket = c.signals, c.ticket
	if req.RunID == "" {
		req.RunID = c.runID
	}
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

// RunSession asks the daemon for a scoped session.
func (c *Client) RunSession(rr RunRequest) (Response, error) {
	return c.roundTrip(Request{Op: OpRunSession, Run: &rr})
}

// SetRun ties the traffic this client relays to a decided run.
func (c *Client) SetRun(id string) { c.runID = id }

// ReportExit tells the daemon how the run set with SetRun ended.
func (c *Client) ReportExit(code int) error {
	if c.runID == "" {
		return nil
	}
	_, err := c.roundTrip(Request{Op: OpRunExit, Exit: code})
	return err
}

// EndSession revokes a placeholder session.
func (c *Client) EndSession(id string) error {
	_, err := c.roundTrip(Request{Op: OpEndSession, Proxy: id})
	return err
}

// Credential asks the daemon for the placeholder a git credential helper
// returns for a host. A nil result means the daemon has none to offer.
func (c *Client) Credential(session string, req CredentialRequest) (*Credential, error) {
	resp, err := c.roundTrip(Request{Op: OpCredential, Proxy: session, Credential: &req})
	if err != nil {
		return nil, err
	}
	return resp.Credential, nil
}

// Socket is the control socket path the client talks to.
func (c *Client) Socket() string { return c.socket }

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
	return c.forward(Request{Op: OpGateway})
}

// ForwardProxy is Forward for a placeholder session: each connection becomes a
// client connection of the session's proxy.
func (c *Client) ForwardProxy(id string) (addr string, stop func(), err error) {
	return c.forward(Request{Op: OpProxy, Proxy: id})
}

func (c *Client) forward(req Request) (addr string, stop func(), err error) {
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
				c.relay(conn, req)
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

func (c *Client) relay(local net.Conn, req Request) {
	up, err := c.dial()
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	if err := writeFrame(up, c.stamp(req)); err != nil {
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
