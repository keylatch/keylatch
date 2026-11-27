package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	handshakeTimeout = 30 * time.Second
	defaultMaxFails  = 5
)

// Reasons reported for a connection.
const (
	ReasonConnected      = "connected"
	ReasonBadToken       = "bad_token"
	ReasonUpstreamFailed = "upstream_failed"
	ReasonRefused        = "refused"
	ReasonCancel         = "cancel"
)

// Config describes one adapter session.
type Config struct {
	// Token is the password the client must present. It is useless outside
	// this session.
	Token string
	// Target is the upstream database, host:port.
	Target string
	// User is the upstream role; the client's user name is ignored.
	User string
	// Database is used when the client names none.
	Database string
	// Password returns the stored credential. It is read per connection and the
	// caller of Password never keeps it.
	Password func(ctx context.Context) ([]byte, error)
	// TLS configures the upstream TLS connection. A nil value verifies the
	// server certificate against the system roots for the target's host name.
	TLS *tls.Config
	// PlainUpstream permits an upstream without TLS; without it a server that
	// does not offer TLS is refused.
	PlainUpstream bool
	// Dial replaces the network, for tests.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Report receives one reason per connection. It never sees a secret.
	Report func(reason string)
	// MaxAuthFailures ends the session's service after this many wrong tokens;
	// zero selects five.
	MaxAuthFailures int
}

// Server serves the connections of one session.
type Server struct {
	cfg   Config
	fails atomic.Int32

	mu      sync.Mutex
	cancels map[[2]uint32]struct{}
}

// New returns a Server for the session.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Token == "", cfg.Target == "", cfg.User == "", cfg.Password == nil:
		return nil, errors.New("postgres: a token, target, user and password source are required")
	}
	if _, _, err := net.SplitHostPort(cfg.Target); err != nil {
		return nil, fmt.Errorf("postgres: target %q: %w", cfg.Target, err)
	}
	if cfg.MaxAuthFailures <= 0 {
		cfg.MaxAuthFailures = defaultMaxFails
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{Timeout: handshakeTimeout}).DialContext
	}
	if cfg.Database == "" {
		cfg.Database = "postgres"
	}
	return &Server{cfg: cfg, cancels: map[[2]uint32]struct{}{}}, nil
}

func (s *Server) report(reason string) {
	if s.cfg.Report != nil {
		s.cfg.Report(reason)
	}
}

// Serve handles one client connection and closes it.
func (s *Server) Serve(ctx context.Context, client net.Conn) {
	defer closeGracefully(client)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))

	st, ok := s.clientStartup(ctx, client)
	if !ok {
		return
	}
	if !s.authenticateClient(client) {
		return
	}
	up, pending, err := s.connectUpstream(ctx, st)
	if err != nil {
		s.report(ReasonUpstreamFailed)
		_ = writeMessage(client, 'E', errorBody("08006", "Keylatch could not authenticate to the database"))
		return
	}
	defer func() { _ = up.Close() }()

	if writeMessage(client, 'R', authRequest(authOK)) != nil {
		return
	}
	for _, m := range pending {
		if writeMessage(client, m.typ, m.body) != nil {
			return
		}
		if m.typ == 'K' && len(m.body) >= 8 {
			s.rememberCancel(m.body)
		}
	}
	s.report(ReasonConnected)
	_ = client.SetDeadline(time.Time{})
	relay(ctx, client, up)
}

// closeGracefully ends the write side, then drains briefly before closing.
// Closing a TCP socket with unread input makes Windows send a reset, which
// discards replies the client has not read yet, such as an error message.
func closeGracefully(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		_ = tc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = io.CopyN(io.Discard, tc, 64<<10)
	}
	_ = c.Close()
}

// clientStartup answers SSL and GSS requests, serves a cancel request and
// returns the decoded startup message of a normal connection.
func (s *Server) clientStartup(ctx context.Context, client net.Conn) (startup, bool) {
	for range 3 {
		code, body, err := readStartup(client)
		if err != nil {
			return startup{}, false
		}
		switch code {
		case codeSSLRequest, codeGSSRequest:
			// The listener is on loopback inside the caller's sandbox; the token
			// is per session and the database traffic stays on this host.
			if _, err := client.Write([]byte{'N'}); err != nil {
				return startup{}, false
			}
		case codeCancel:
			s.forwardCancel(ctx, body)
			return startup{}, false
		case protocolV3:
			st, err := parseStartup(body)
			if err != nil {
				_ = writeMessage(client, 'E', errorBody("08P01", "invalid startup message"))
				return startup{}, false
			}
			if st.get("replication") != "" {
				s.report(ReasonRefused)
				_ = writeMessage(client, 'E', errorBody("0A000", "replication connections are not available through Keylatch"))
				return startup{}, false
			}
			return st, true
		default:
			_ = writeMessage(client, 'E', errorBody("0A000", "unsupported protocol version"))
			return startup{}, false
		}
	}
	return startup{}, false
}

// authenticateClient asks for the session token as a cleartext password.
func (s *Server) authenticateClient(client net.Conn) bool {
	if int(s.fails.Load()) >= s.cfg.MaxAuthFailures {
		s.report(ReasonRefused)
		_ = writeMessage(client, 'E', errorBody("28000", "too many failed attempts for this session"))
		return false
	}
	if writeMessage(client, 'R', authRequest(authCleartext)) != nil {
		return false
	}
	m, err := readMessage(client)
	if err != nil || m.typ != 'p' {
		return false
	}
	pw, _, ok := cstring(m.body)
	want, got := sha256.Sum256([]byte(s.cfg.Token)), sha256.Sum256([]byte(pw))
	if !ok || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		s.fails.Add(1)
		s.report(ReasonBadToken)
		_ = writeMessage(client, 'E', errorBody("28P01", "password authentication failed"))
		return false
	}
	return true
}

// dialUpstream connects to the target and negotiates TLS.
func (s *Server) dialUpstream(ctx context.Context) (net.Conn, error) {
	conn, err := s.cfg.Dial(ctx, "tcp", s.cfg.Target)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if s.cfg.PlainUpstream {
		return conn, nil
	}
	var req [8]byte
	binary.BigEndian.PutUint32(req[:4], 8)
	binary.BigEndian.PutUint32(req[4:], codeSSLRequest)
	var answer [1]byte
	if _, werr := conn.Write(req[:]); werr != nil {
		_ = conn.Close()
		return nil, werr
	}
	if _, rerr := io.ReadFull(conn, answer[:]); rerr != nil || answer[0] != 'S' {
		_ = conn.Close()
		return nil, errors.New("postgres: the database does not offer TLS")
	}
	host, _, _ := net.SplitHostPort(s.cfg.Target)
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.cfg.TLS != nil {
		cfg = s.cfg.TLS.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("postgres: TLS to the database: %w", err)
	}
	return tc, nil
}

// connectUpstream authenticates with the stored credential and returns the
// messages the server sent up to ReadyForQuery.
func (s *Server) connectUpstream(ctx context.Context, st startup) (net.Conn, []message, error) {
	conn, err := s.dialUpstream(ctx)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (net.Conn, []message, error) {
		_ = conn.Close()
		return nil, nil, err
	}

	params := map[string]string{"user": s.cfg.User, "database": s.cfg.Database}
	order := []string{"user", "database"}
	for _, k := range st.order {
		switch k {
		case "user":
		case "database":
			if v := st.params[k]; v != "" {
				params["database"] = v
			}
		default:
			params[k] = st.params[k]
			order = append(order, k)
		}
	}
	if _, err := conn.Write(encodeStartup(order, params)); err != nil {
		return fail(err)
	}

	var pending []message
	var scram *scramClient
	for {
		m, err := readMessage(conn)
		if err != nil {
			return fail(err)
		}
		switch m.typ {
		case 'E':
			return fail(parseError(m.body))
		case 'R':
			if err := s.answerAuth(ctx, conn, m.body, &scram); err != nil {
				return fail(err)
			}
		case 'Z':
			pending = append(pending, m)
			_ = conn.SetDeadline(time.Time{})
			return conn, pending, nil
		case 'S', 'K', 'N':
			pending = append(pending, m)
		default:
			return fail(errProtocol)
		}
	}
}

// answerAuth responds to one Authentication message from the server.
func (s *Server) answerAuth(ctx context.Context, conn net.Conn, body []byte, scram **scramClient) error {
	if len(body) < 4 {
		return errProtocol
	}
	code := binary.BigEndian.Uint32(body)
	switch code {
	case authOK:
		return nil
	case authMD5:
		// MD5 password auth is deprecated in PostgreSQL and its hash is cheap
		// to brute force from a captured exchange; the adapter speaks SCRAM.
		return errors.New("postgres: the database asks for MD5 password auth; configure scram-sha-256 for this role")
	case authCleartext:
		pw, err := s.cfg.Password(ctx)
		if err != nil {
			return err
		}
		defer clear(pw)
		out := make([]byte, 0, len(pw)+1)
		out = append(append(out, pw...), 0)
		defer clear(out)
		return writeMessage(conn, 'p', out)
	case authSASL:
		if !hasMechanism(body[4:], scramMechanism) {
			return errors.New("postgres: the database offers no supported SASL mechanism")
		}
		pw, err := s.cfg.Password(ctx)
		if err != nil {
			return err
		}
		defer clear(pw)
		c, err := newSCRAMClient(string(pw))
		if err != nil {
			return err
		}
		*scram = c
		first := c.first()
		msg := append([]byte(scramMechanism), 0)
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(first))) //nolint:gosec // G115: the client-first message is a few dozen bytes
		return writeMessage(conn, 'p', append(msg, first...))
	case authSASLContinu:
		if *scram == nil {
			return errProtocol
		}
		final, err := (*scram).final(body[4:])
		if err != nil {
			return err
		}
		return writeMessage(conn, 'p', final)
	case authSASLFinal:
		if *scram == nil {
			return errProtocol
		}
		return (*scram).verify(body[4:])
	default:
		return fmt.Errorf("postgres: unsupported authentication method %d", code)
	}
}

func (s *Server) rememberCancel(keyData []byte) {
	k := [2]uint32{binary.BigEndian.Uint32(keyData), binary.BigEndian.Uint32(keyData[4:])}
	s.mu.Lock()
	s.cancels[k] = struct{}{}
	s.mu.Unlock()
}

// forwardCancel relays a query cancellation for a backend this session
// started. A key it did not hand out is dropped.
func (s *Server) forwardCancel(ctx context.Context, body []byte) {
	if len(body) != 8 {
		return
	}
	k := [2]uint32{binary.BigEndian.Uint32(body), binary.BigEndian.Uint32(body[4:])}
	s.mu.Lock()
	_, known := s.cancels[k]
	s.mu.Unlock()
	if !known {
		return
	}
	conn, err := s.dialUpstream(ctx)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	pkt := make([]byte, 16)
	binary.BigEndian.PutUint32(pkt, 16)
	binary.BigEndian.PutUint32(pkt[4:], codeCancel)
	copy(pkt[8:], body)
	_, _ = conn.Write(pkt)
	s.report(ReasonCancel)
}

// relay copies both directions until either side closes or ctx ends.
func relay(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go pipe(a, b)
	go pipe(b, a)
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = a.Close()
	_ = b.Close()
}
