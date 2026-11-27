package redis

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

const token = "klph_redis_session"

func client(t *testing.T, s *Server) (net.Conn, *bufio.Reader, context.CancelFunc) {
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
	return near, bufio.NewReader(near), cancel
}

func TestAuthentication(t *testing.T) {
	for _, args := range [][]string{{"AUTH", token}, {"auth", "ignored-user", token}, {"HELLO", "3", "AUTH", "ignored", token}, {"hello", "2", "auth", "ignored", token, "SETNAME", "client"}} {
		got, _ := authentication(args)
		assert.Equal(t, token, got)
	}
	for _, args := range [][]string{nil, {"PING"}, {"AUTH"}, {"AUTH", "a", "b", "c"}, {"HELLO", "4", "AUTH", "u", token}, {"HELLO", "3", "AUTH", "u", token, "evil", "x"}} {
		got, _ := authentication(args)
		assert.Empty(t, got)
	}
}

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	require.NoError(t, writeCommand(&b, "AUTH", "user", "password"))
	got, err := readCommand(bufio.NewReader(&b))
	require.NoError(t, err)
	assert.Equal(t, []string{"AUTH", "user", "password"}, got)
	for _, frame := range []string{"", "+OK\r\n", "*17\r\n", "*-1\r\n", "*x\r\n", "*1\r\n$65537\r\n", "*1\r\n$-1\r\n", "*1\r\n$1\r\nx!!", "*1\r\n$1\r\n", "*1\n", strings.Repeat("x", 5000)} {
		_, err := readCommand(bufio.NewReader(strings.NewReader(frame)))
		assert.Error(t, err)
	}
}

func TestConfiguration(t *testing.T) {
	for _, cfg := range []Config{{}, {Token: token, Target: "host:6379"}, {Token: token, Target: "bad", Password: func(context.Context) ([]byte, error) { return nil, nil }}} {
		_, err := New(cfg)
		assert.Error(t, err)
	}
	s, err := New(Config{Token: token, Target: "host:6379", Password: func(context.Context) ([]byte, error) { return nil, nil }})
	require.NoError(t, err)
	assert.Equal(t, "default", s.cfg.User)
	assert.NotNil(t, s.cfg.Dial)
}

func TestBadTokenNeverReadsOrDials(t *testing.T) {
	var calls atomic.Int32
	s, err := New(Config{Token: token, Target: "cache.example:6379", MaxAuthFailures: 2,
		Password: func(context.Context) ([]byte, error) { calls.Add(1); return nil, nil },
		Dial: func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, errors.New("unexpected dial")
		},
	})
	require.NoError(t, err)
	for range 2 {
		c, r, _ := client(t, s)
		require.NoError(t, writeCommand(c, "AUTH", "stored-password"))
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		assert.Contains(t, line, "WRONGPASS")
	}
	c, _, _ := client(t, s)
	_, err = c.Read(make([]byte, 1))
	assert.Error(t, err)
	assert.Zero(t, calls.Load())
}

func TestRelayAuthenticatesUpstreamAndWipesPassword(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	defer certServer.Close()
	for _, plain := range []bool{true, false} {
		for _, hello := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{true: "plain", false: "tls"}[plain], map[bool]string{true: "hello", false: "auth"}[hello]}, "/"), func(t *testing.T) {
				password := []byte("stored-redis-password")
				auth := make(chan []string, 2)
				s, err := New(Config{Token: token, Target: "cache.example:6379", User: "app", PlainUpstream: plain,
					TLS:      &tls.Config{RootCAs: certServer.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: "example.com", MinVersion: tls.VersionTLS12},
					Password: func(context.Context) ([]byte, error) { return password, nil },
					Dial: func(context.Context, string, string) (net.Conn, error) {
						near, far := net.Pipe()
						go func() {
							defer far.Close()
							conn := far
							if !plain {
								conn = tls.Server(far, certServer.TLS)
							}
							r := bufio.NewReader(conn)
							args, err := readCommand(r)
							if err != nil {
								return
							}
							auth <- args
							_, _ = io.WriteString(conn, "+OK\r\n")
							if hello {
								args, err = readCommand(r)
								if err != nil {
									return
								}
								auth <- args
								_, _ = io.WriteString(conn, "%0\r\n")
							}
							args, err = readCommand(r)
							if err != nil {
								return
							}
							_ = writeCommand(conn, args...)
							_, _ = io.Copy(io.Discard, r)
						}()
						return near, nil
					},
				})
				require.NoError(t, err)
				c, r, cancel := client(t, s)
				if hello {
					require.NoError(t, writeCommand(c, "HELLO", "3", "AUTH", "ignored", token, "SETNAME", "client"))
				} else {
					require.NoError(t, writeCommand(c, "AUTH", token))
				}
				line, err := r.ReadString('\n')
				require.NoError(t, err)
				assert.Contains(t, []string{"+OK\r\n", "%0\r\n"}, line)
				assert.Equal(t, []string{"AUTH", "app", "stored-redis-password"}, <-auth)
				assert.Equal(t, make([]byte, len(password)), password)
				if hello {
					assert.Equal(t, []string{"HELLO", "3", "SETNAME", "client"}, <-auth)
				}
				require.NoError(t, writeCommand(c, "PING"))
				args, err := readCommand(r)
				require.NoError(t, err)
				assert.Equal(t, []string{"PING"}, args)
				cancel()
				_, err = r.ReadByte()
				assert.Error(t, err)
			})
		}
	}
}

func TestUpstreamFailureIsSanitized(t *testing.T) {
	for _, mode := range []string{"dial", "credential", "empty", "auth", "tls"} {
		t.Run(mode, func(t *testing.T) {
			s, err := New(Config{Token: token, Target: "cache.example:6379", PlainUpstream: mode != "tls",
				Password: func(context.Context) ([]byte, error) {
					if mode == "credential" {
						return nil, errors.New("stored-secret")
					}
					if mode == "empty" {
						return nil, nil
					}
					return []byte("stored-secret"), nil
				},
				Dial: func(context.Context, string, string) (net.Conn, error) {
					if mode == "dial" {
						return nil, errors.New("stored-secret")
					}
					near, far := net.Pipe()
					go func() {
						defer far.Close()
						if mode == "tls" {
							return
						}
						_, _ = readCommand(bufio.NewReader(far))
						_, _ = io.WriteString(far, "-WRONGPASS stored-secret\r\n")
					}()
					return near, nil
				},
			})
			require.NoError(t, err)
			c, r, _ := client(t, s)
			require.NoError(t, writeCommand(c, "AUTH", token))
			line, err := r.ReadString('\n')
			require.NoError(t, err)
			assert.Contains(t, line, "could not authenticate")
			assert.NotContains(t, line, "stored-secret")
		})
	}
}
