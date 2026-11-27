// Package redis terminates Redis and Valkey authentication with a session token.
package redis

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const handshakeTimeout = 30 * time.Second

// Config binds one session to an upstream ACL user and credential source.
type Config struct {
	Token, Target, User string
	Password            func(context.Context) ([]byte, error)
	TLS                 *tls.Config
	PlainUpstream       bool
	Dial                func(context.Context, string, string) (net.Conn, error)
	Report              func(string)
	MaxAuthFailures     int
}

// Server serves authenticated connections until their session ends.
type Server struct {
	cfg   Config
	fails atomic.Int64
}

// New validates the session configuration. TLS is required unless explicitly disabled.
func New(cfg Config) (*Server, error) {
	if cfg.Token == "" || cfg.Target == "" || cfg.Password == nil {
		return nil, errors.New("redis: a token, target and password source are required")
	}
	if _, _, err := net.SplitHostPort(cfg.Target); err != nil {
		return nil, errors.New("redis: target must be host:port")
	}
	if cfg.User == "" {
		cfg.User = "default"
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

// Serve authenticates both sides, then relays traffic without exposing the stored password.
func (s *Server) Serve(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
	if s.fails.Load() >= int64(s.cfg.MaxAuthFailures) {
		s.report("refused")
		return
	}
	r := bufio.NewReader(client)
	args, err := readCommand(r)
	if err != nil {
		s.report("refused")
		return
	}
	token, hello := authentication(args)
	want, got := sha256.Sum256([]byte(s.cfg.Token)), sha256.Sum256([]byte(token))
	if token == "" || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		s.fails.Add(1)
		s.report("bad_token")
		_, _ = io.WriteString(client, "-WRONGPASS invalid session token\r\n")
		return
	}
	up, err := s.connect(ctx)
	if err != nil {
		s.report("upstream_failed")
		_, _ = io.WriteString(client, "-ERR Keylatch could not authenticate to the database\r\n")
		return
	}
	defer func() { _ = up.Close() }()
	stopUp := context.AfterFunc(ctx, func() { _ = up.Close() })
	defer stopUp()
	if hello != nil {
		if err := writeCommand(up, hello...); err != nil {
			s.report("upstream_failed")
			return
		}
	} else if _, err := io.WriteString(client, "+OK\r\n"); err != nil {
		return
	}
	s.report("connected")
	_ = client.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { _, _ = io.Copy(up, r); _ = up.Close(); close(done) }()
	_, _ = io.Copy(client, up)
	_ = client.Close()
	_ = up.Close()
	<-done
}

func authentication(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	switch strings.ToUpper(args[0]) {
	case "AUTH":
		if len(args) == 2 || len(args) == 3 {
			return args[len(args)-1], nil
		}
	case "HELLO":
		if (len(args) == 5 || len(args) == 7) && (args[1] == "2" || args[1] == "3") && strings.EqualFold(args[2], "AUTH") {
			hello := []string{"HELLO", args[1]}
			if len(args) == 7 {
				if !strings.EqualFold(args[5], "SETNAME") {
					return "", nil
				}
				hello = append(hello, "SETNAME", args[6])
			}
			return args[4], hello
		}
	}
	return "", nil
}

func (s *Server) connect(ctx context.Context) (net.Conn, error) {
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
	if !s.cfg.PlainUpstream {
		host, _, _ := net.SplitHostPort(s.cfg.Target)
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
		if s.cfg.TLS != nil {
			cfg = s.cfg.TLS.Clone()
			if cfg.ServerName == "" {
				cfg.ServerName = host
			}
		}
		tlsConn := tls.Client(up, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		up = tlsConn
	}
	password, err := s.cfg.Password(ctx)
	if err != nil {
		clear(password)
		return nil, err
	}
	if len(password) == 0 {
		return nil, errors.New("redis: empty credential")
	}
	err = writeAuth(up, s.cfg.User, password)
	clear(password)
	if err != nil {
		return nil, err
	}
	// Authentication is RESP2; read exactly one line without buffering later replies.
	var response [5]byte
	if _, err := io.ReadFull(up, response[:]); err != nil {
		return nil, err
	}
	if string(response[:]) != "+OK\r\n" {
		return nil, errors.New("redis: upstream authentication failed")
	}
	ok = true
	return up, nil
}

func writeAuth(w io.Writer, user string, password []byte) error {
	if _, err := fmt.Fprintf(w, "*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n", len(user), user, len(password)); err != nil {
		return err
	}
	if _, err := w.Write(password); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func writeCommand(w io.Writer, args ...string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(args)); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(arg), arg); err != nil {
			return err
		}
	}
	return nil
}

func readCommand(r *bufio.Reader) ([]string, error) {
	n, err := readLength(r, '*', 16)
	if err != nil {
		return nil, err
	}
	args := make([]string, n)
	for i := range args {
		size, err := readLength(r, '$', 64<<10)
		if err != nil {
			return nil, err
		}
		value := make([]byte, size+2)
		if _, err := io.ReadFull(r, value); err != nil {
			return nil, err
		}
		if string(value[size:]) != "\r\n" {
			return nil, errors.New("redis: invalid bulk string")
		}
		args[i] = string(value[:size])
	}
	return args, nil
}

func readLength(r *bufio.Reader, prefix byte, max int) (int, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return 0, err
	}
	if len(line) < 4 || line[0] != prefix || line[len(line)-2] != '\r' {
		return 0, errors.New("redis: invalid frame")
	}
	n, err := strconv.Atoi(string(line[1 : len(line)-2]))
	if err != nil || n < 0 || n > max {
		return 0, errors.New("redis: frame exceeds limit")
	}
	return n, nil
}
