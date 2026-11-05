package mysql

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testToken = "klph_mysql_session"

func TestWireValidation(t *testing.T) {
	nonce := bytes.Repeat([]byte{'x'}, 20)
	caps, got, err := parseGreeting(greeting(nonce))
	require.NoError(t, err)
	assert.Equal(t, uint32(capabilities), caps)
	assert.Equal(t, nonce, got)
	auth := scramble([]byte(testToken), nonce)
	l, err := parseLogin(loginPacket(capabilities, 45, "user", "db", auth))
	require.NoError(t, err)
	assert.Equal(t, "db", l.database)
	assert.Equal(t, auth, l.auth)
	for _, body := range [][]byte{nil, {10}, bytes.Repeat([]byte{0}, 64), append([]byte{9}, greeting(nonce)[1:]...), bytes.ReplaceAll(greeting(nonce), []byte(plugin), []byte("unknown"))} {
		_, _, err := parseGreeting(body)
		assert.Error(t, err)
	}
	for _, body := range [][]byte{nil, make([]byte, 32), loginPacket(capabilities|ssl, 45, "u", "d", auth), loginPacket(0, 45, "u", "", auth), bytes.ReplaceAll(loginPacket(capabilities, 45, "u", "d", auth), []byte(plugin), []byte("unknown"))} {
		_, err := parseLogin(body)
		assert.Error(t, err)
	}
	var b bytes.Buffer
	require.NoError(t, writePacket(&b, 7, []byte("hello")))
	p, err := readPacket(&b, 7)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), p)
	for _, frame := range [][]byte{nil, {0, 0, 0, 0}, {1, 0, 0, 1, 'a'}, {255, 255, 255, 0}, {1, 0, 0, 0}} {
		_, err := readPacket(bytes.NewReader(frame), 0)
		assert.Error(t, err)
	}
	assert.Error(t, writePacket(io.Discard, 0, make([]byte, (1<<20)+1)))
}

func TestNew(t *testing.T) {
	password := func(context.Context) ([]byte, error) { return []byte("stored-password"), nil }
	for _, cfg := range []Config{{}, {Token: testToken, Target: "bad", User: "u", Password: password}, {Token: testToken, Target: "db:3306", User: "u\x00", Password: password}} {
		_, err := New(cfg)
		assert.Error(t, err)
	}
	s, err := New(Config{Token: testToken, Target: "db:3306", User: "u", Password: password})
	require.NoError(t, err)
	assert.NotNil(t, s.cfg.Dial)
	assert.Equal(t, 5, s.cfg.MaxAuthFailures)
}

func startClient(t *testing.T, s *Server) (net.Conn, context.CancelFunc) {
	t.Helper()
	near, far := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Serve(ctx, far); close(done) }()
	_ = near.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() {
		cancel()
		_ = near.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("adapter did not stop")
		}
	})
	return near, cancel
}

func loginClient(t *testing.T, c net.Conn, password, database string) {
	t.Helper()
	body, err := readPacket(c, 0)
	require.NoError(t, err)
	_, nonce, err := parseGreeting(body)
	require.NoError(t, err)
	require.NoError(t, writePacket(c, 1, loginPacket(capabilities, 45, "ignored", database, scramble([]byte(password), nonce))))
}

func TestBadLoginDoesNotReadSecrets(t *testing.T) {
	var calls atomic.Int32
	s, err := New(Config{Token: testToken, Target: "db:3306", User: "u", Database: "bound", MaxAuthFailures: 1, Password: func(context.Context) ([]byte, error) { calls.Add(1); return nil, nil }})
	require.NoError(t, err)
	c, _ := startClient(t, s)
	loginClient(t, c, "stored-password", "bound")
	body, err := readPacket(c, 2)
	require.NoError(t, err)
	assert.Equal(t, byte(255), body[0])
	assert.Zero(t, calls.Load())
	c, _ = startClient(t, s)
	_, err = readPacket(c, 0)
	assert.Error(t, err)
	s.cfg.MaxAuthFailures = 5
	c, _ = startClient(t, s)
	loginClient(t, c, testToken, "other")
	body, err = readPacket(c, 2)
	require.NoError(t, err)
	assert.Equal(t, byte(255), body[0])
	assert.Zero(t, calls.Load())
}

func fakeUpstream(t *testing.T, mode string, serverTLS *tls.Config, seen chan<- []byte) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(context.Context, string, string) (net.Conn, error) {
		if mode == "dial" {
			return nil, errors.New("stored-secret")
		}
		near, far := net.Pipe()
		go func() {
			defer func() { _ = far.Close() }()
			_ = far.SetDeadline(time.Now().Add(5 * time.Second))
			nonce := bytes.Repeat([]byte{'n'}, 20)
			hello := greeting(nonce)
			if serverTLS != nil {
				offset := 1 + len("8.0.0-Keylatch") + 1 + 13
				binary.LittleEndian.PutUint16(hello[offset:], uint16((capabilities|ssl)&65535))
			}
			if mode == "greeting" {
				hello[0] = 9
			}
			if writePacket(far, 0, hello) != nil {
				return
			}
			seq := byte(1)
			conn := far
			body, err := readPacket(conn, seq)
			if err != nil {
				return
			}
			seq++
			if serverTLS != nil {
				conn = tls.Server(far, serverTLS)
				body, err = readPacket(conn, seq)
				if err != nil {
					return
				}
				seq++
			}
			if seen != nil {
				seen <- body
			}
			switch mode {
			case "auth_error":
				_ = writePacket(conn, seq, []byte{255, 1, 2})
				return
			case "continuation":
				_ = writePacket(conn, seq, []byte{1, 9})
				return
			case "short":
				_ = writePacket(conn, seq, []byte{1})
				return
			case "switch":
				if writePacket(conn, seq, append(append([]byte{254}, []byte(plugin+"\x00")...), append(nonce, 0)...)) != nil {
					return
				}
				seq++
				if _, err = readPacket(conn, seq); err != nil {
					return
				}
				seq++
			case "bad_switch":
				_ = writePacket(conn, seq, []byte{254, 'x', 0})
				return
			case "full":
				if writePacket(conn, seq, []byte{1, 4}) != nil {
					return
				}
				seq++
				body, err = readPacket(conn, seq)
				if err != nil {
					return
				}
				seq++
				if seen != nil {
					seen <- body
				}
			case "fast":
				if writePacket(conn, seq, []byte{1, 3}) != nil {
					return
				}
				seq++
			}
			if writePacket(conn, seq, []byte{0, 0, 0, 2, 0, 0, 0}) != nil {
				return
			}
			body, err = readPacket(conn, 0)
			if err != nil {
				return
			}
			_ = writePacket(conn, 1, body)
			_, _ = io.Copy(io.Discard, conn)
		}()
		return near, nil
	}
}

func TestAuthenticationAndRelay(t *testing.T) {
	cert := httptest.NewTLSServer(nil)
	defer cert.Close()
	for _, mode := range []string{"ok", "fast", "full", "switch"} {
		t.Run(mode, func(t *testing.T) {
			password := []byte("stored-password")
			seen := make(chan []byte, 2)
			s, err := New(Config{Token: testToken, Target: "db.example:3306", User: "app", Database: "bound", Password: func(context.Context) ([]byte, error) { return password, nil },
				TLS: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "example.com", RootCAs: cert.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}, Dial: fakeUpstream(t, mode, cert.TLS, seen)})
			require.NoError(t, err)
			c, cancel := startClient(t, s)
			loginClient(t, c, testToken, "bound")
			body, err := readPacket(c, 2)
			require.NoError(t, err)
			require.Equal(t, []byte{1, 3}, body)
			body, err = readPacket(c, 3)
			require.NoError(t, err)
			require.Equal(t, byte(0), body[0])
			assert.Contains(t, string(<-seen), "app\x00")
			assert.Equal(t, make([]byte, len(password)), password)
			if mode == "full" {
				assert.Equal(t, []byte("stored-password\x00"), <-seen)
			}
			require.NoError(t, writePacket(c, 0, []byte{14}))
			body, err = readPacket(c, 1)
			require.NoError(t, err)
			assert.Equal(t, []byte{14}, body)
			cancel()
			_, err = readPacket(c, 0)
			assert.Error(t, err)
		})
	}
}

func TestUpstreamErrorsAreSanitized(t *testing.T) {
	cert := httptest.NewTLSServer(nil)
	defer cert.Close()
	for _, mode := range []string{"dial", "greeting", "credential", "empty", "auth_error", "continuation", "short", "bad_switch", "require_tls", "untrusted_tls"} {
		t.Run(mode, func(t *testing.T) {
			var serverTLS *tls.Config
			if mode == "untrusted_tls" {
				serverTLS = cert.TLS
			}
			s, err := New(Config{Token: testToken, Target: "db:3306", User: "app", PlainUpstream: mode != "require_tls" && mode != "untrusted_tls", Password: func(context.Context) ([]byte, error) {
				if mode == "credential" {
					return nil, errors.New("stored-secret")
				}
				if mode == "empty" {
					return nil, nil
				}
				return []byte("stored-secret"), nil
			}, Dial: fakeUpstream(t, mode, serverTLS, nil)})
			require.NoError(t, err)
			c, _ := startClient(t, s)
			loginClient(t, c, testToken, "")
			body, err := readPacket(c, 2)
			require.NoError(t, err)
			assert.Equal(t, byte(255), body[0])
			assert.NotContains(t, string(body), "stored-secret")
		})
	}
}

func TestBoundedPacketParsing(t *testing.T) {
	for n := 0; n < 80; n++ {
		b := bytes.Repeat([]byte{'x'}, n)
		_, _, _ = parseGreeting(b)
		_, _ = parseLogin(b)
	}
	_, err := parseLogin(append(loginPacket(capabilities, 45, "user", "db", nil)[:32], []byte(strings.Repeat("x", 100))...))
	assert.Error(t, err)
}
