// Package mysql terminates MySQL authentication with per-session credentials.
package mysql

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

const handshakeTimeout = 30 * time.Second

// Config binds one session to an upstream role, database and stored password.
type Config struct {
	Token, Target, User, Database string
	Password                      func(context.Context) ([]byte, error)
	TLS                           *tls.Config
	PlainUpstream                 bool
	Dial                          func(context.Context, string, string) (net.Conn, error)
	Report                        func(string)
	MaxAuthFailures               int
}

// Server authenticates connections for one session.
type Server struct {
	cfg   Config
	fails atomic.Int64
}

// New validates a session. Upstream TLS is required by default.
func New(cfg Config) (*Server, error) {
	if cfg.Token == "" || cfg.Target == "" || cfg.User == "" || cfg.Password == nil || strings.ContainsAny(cfg.User+cfg.Database, "\x00") {
		return nil, errors.New("mysql: a token, target, user and password source are required")
	}
	if _, _, err := net.SplitHostPort(cfg.Target); err != nil {
		return nil, errors.New("mysql: target must be host:port")
	}
	if cfg.MaxAuthFailures <= 0 {
		cfg.MaxAuthFailures = 5
	}
	if cfg.Dial == nil {
		cfg.Dial = (&net.Dialer{Timeout: handshakeTimeout}).DialContext
	}
	return &Server{cfg: cfg}, nil
}

func (s *Server) report(reason string) {
	if s.cfg.Report != nil {
		s.cfg.Report(reason)
	}
}

// Serve authenticates the client before reading a secret or contacting the database.
func (s *Server) Serve(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	if s.fails.Load() >= int64(s.cfg.MaxAuthFailures) {
		s.report("refused")
		return
	}
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if err := writePacket(client, 0, greeting(nonce)); err != nil {
		return
	}
	body, err := readPacket(client, 1)
	if err != nil {
		s.report("refused")
		return
	}
	l, err := parseLogin(body)
	if err != nil {
		s.report("refused")
		refuse(client, 2)
		return
	}
	want := scramble([]byte(s.cfg.Token), nonce)
	if subtle.ConstantTimeCompare(want, l.auth) != 1 {
		s.fails.Add(1)
		s.report("bad_token")
		refuse(client, 2)
		return
	}
	if s.cfg.Database != "" && l.database != "" && l.database != s.cfg.Database {
		s.report("refused")
		refuse(client, 2)
		return
	}
	up, err := s.connect(ctx, l)
	if err != nil {
		s.report("upstream_failed")
		refuse(client, 2)
		return
	}
	defer func() { _ = up.Close() }()
	stopUp := context.AfterFunc(ctx, func() { _ = up.Close() })
	defer stopUp()
	if writePacket(client, 2, []byte{1, 3}) != nil {
		return
	}
	if writePacket(client, 3, []byte{0, 0, 0, 2, 0, 0, 0}) != nil {
		return
	}
	s.report("connected")
	_ = client.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { _, _ = io.Copy(up, client); _ = up.Close(); close(done) }()
	_, _ = io.Copy(client, up)
	_ = client.Close()
	_ = up.Close()
	<-done
}

func (s *Server) connect(ctx context.Context, l login) (net.Conn, error) {
	up, err := s.cfg.Dial(ctx, "tcp", s.cfg.Target)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = up.Close()
		}
	}()
	raw := up
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	_ = up.SetDeadline(time.Now().Add(handshakeTimeout))
	body, err := readPacket(up, 0)
	if err != nil {
		return nil, err
	}
	caps, nonce, err := parseGreeting(body)
	if err != nil {
		return nil, err
	}
	flags := l.caps & capabilities
	if s.cfg.Database != "" {
		flags |= connectDB
		l.database = s.cfg.Database
	}
	if flags&caps != flags {
		return nil, errors.New("mysql: upstream lacks required capabilities")
	}
	seq := byte(1)
	if !s.cfg.PlainUpstream {
		if caps&ssl == 0 {
			return nil, errors.New("mysql: upstream TLS is required")
		}
		flags |= ssl
		request := loginPacket(flags, l.charset, "", "", nil)[:32]
		if err := writePacket(up, seq, request); err != nil {
			return nil, err
		}
		seq++
		host, _, _ := net.SplitHostPort(s.cfg.Target)
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
		if s.cfg.TLS != nil {
			cfg = s.cfg.TLS.Clone()
			if cfg.ServerName == "" {
				cfg.ServerName = host
			}
		}
		tc := tls.Client(up, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		up = tc
	}
	password, err := s.cfg.Password(ctx)
	if err != nil {
		clear(password)
		return nil, err
	}
	defer clear(password)
	if len(password) == 0 || bytes.IndexByte(password, 0) >= 0 {
		return nil, errors.New("mysql: invalid stored password")
	}
	auth := scramble(password, nonce)
	if err := writePacket(up, seq, loginPacket(flags, l.charset, s.cfg.User, l.database, auth)); err != nil {
		return nil, err
	}
	seq++
	for range 5 {
		body, err = readPacket(up, seq)
		if err != nil {
			return nil, err
		}
		seq++
		switch body[0] {
		case 0:
			ok = true
			return up, nil
		case 1:
			if len(body) != 2 {
				return nil, errors.New("mysql: invalid authentication continuation")
			}
			switch body[1] {
			case 3:
				continue
			case 4:
				full := append(append([]byte(nil), password...), 0)
				err = writePacket(up, seq, full)
				clear(full)
				if err != nil {
					return nil, err
				}
				seq++
			default:
				return nil, errors.New("mysql: unsupported authentication continuation")
			}
		case 254:
			name, challenge, err := takeString(body[1:])
			if err != nil || name != plugin || len(challenge) != 21 {
				return nil, errors.New("mysql: unsupported authentication switch")
			}
			auth = scramble(password, challenge[:20])
			if err := writePacket(up, seq, auth); err != nil {
				return nil, err
			}
			seq++
		default:
			return nil, errors.New("mysql: upstream authentication failed")
		}
	}
	return nil, errors.New("mysql: excessive authentication exchanges")
}
