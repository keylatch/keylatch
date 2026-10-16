package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	realUser     = "app_owner"
	realPassword = "db-password-that-must-stay-here-0123"
	sessionToken = "klph_session_token_0123456789abcdef"
)

type reports struct {
	mu   sync.Mutex
	list []string
}

func (r *reports) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.list = append(r.list, s)
}

func (r *reports) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.list...)
}

func (r *reports) waitFor(t *testing.T, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, s := range r.all() {
			if s == want {
				return true
			}
		}
		return false
	}, 5*time.Second, 5*time.Millisecond, "reasons: %v", r.all())
}

// serveAdapter listens on loopback and serves every connection with srv.
func serveAdapter(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.Serve(ctx, c)
		}
	}()
	return ln.Addr().String()
}

func newAdapter(t *testing.T, upstream string, mutate func(*Config)) (*Server, *reports) {
	t.Helper()
	rep := &reports{}
	cfg := Config{
		Token: sessionToken, Target: upstream, User: realUser, Database: "postgres",
		Password:      func(context.Context) ([]byte, error) { return []byte(realPassword), nil },
		PlainUpstream: true,
		Report:        rep.add,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg)
	require.NoError(t, err)
	return srv, rep
}

func TestUpstreamAuthenticationMethods(t *testing.T) {
	for _, mode := range []string{modeScram, modeMD5, modeCleartext} {
		t.Run(mode, func(t *testing.T) {
			pg := startFakePG(t, mode, realUser, realPassword, nil)
			srv, rep := newAdapter(t, pg.addr(), nil)
			addr := serveAdapter(t, srv)

			c := dialClient(t, addr, "klph", "appdb", sessionToken)
			require.Nil(t, c.authError)
			assert.Equal(t, realUser+"@appdb", c.query(t, "select current_user"), "the database saw the real role and the client's database")
			rep.waitFor(t, ReasonConnected)

			starts := pg.seenStartups()
			require.Len(t, starts, 1)
			assert.Equal(t, realUser, starts[0]["user"], "the client's user name never reaches the database")
			assert.NotContains(t, c.raw.String(), realPassword, "the password never reaches the client")
			assert.NotContains(t, c.raw.String(), "klph_session", "the client is not sent its own token back")
		})
	}
}

// A real libpq client, when one is installed, speaks to the adapter in front of
// the fake server: the framing, the cleartext login and the relay hold up
// against an implementation this package did not write.
func TestPsqlThroughTheAdapter(t *testing.T) {
	psql, err := exec.LookPath("psql")
	if err != nil {
		t.Skip("psql is not installed")
	}
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, _ := newAdapter(t, pg.addr(), nil)
	host, port, err := net.SplitHostPort(serveAdapter(t, srv))
	require.NoError(t, err)

	run := func(password string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, psql, "-w", "-tAc", "select current_user", "-d", "appdb")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "PGHOST=" + host, "PGPORT=" + port, "PGUSER=klph", "PGPASSWORD=" + password, "PGSSLMODE=prefer"}
		return cmd.CombinedOutput()
	}
	out, err := run(sessionToken)
	require.NoError(t, err, string(out))
	assert.Equal(t, realUser+"@appdb", strings.TrimSpace(string(out)))

	out, err = run(realPassword)
	require.Error(t, err)
	assert.Contains(t, string(out), "password authentication failed")
}

func TestClientParametersAreForwardedAndTheDefaultDatabaseApplies(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, _ := newAdapter(t, pg.addr(), func(c *Config) { c.Database = "fallback" })
	addr := serveAdapter(t, srv)

	c := dialClient(t, addr, "klph", "", sessionToken, "application_name", "psql", "client_encoding", "UTF8")
	require.Nil(t, c.authError)
	assert.Equal(t, realUser+"@fallback", c.query(t, "select 1"))
	starts := pg.seenStartups()
	require.Len(t, starts, 1)
	assert.Equal(t, "psql", starts[0]["application_name"])
	assert.Equal(t, "UTF8", starts[0]["client_encoding"])
}

func TestAWrongTokenNeverReachesTheDatabase(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, rep := newAdapter(t, pg.addr(), nil)
	addr := serveAdapter(t, srv)

	c := dialClient(t, addr, "klph", "appdb", "not-the-token")
	require.NotNil(t, c.authError)
	assert.Equal(t, "28P01", c.authError.code)
	rep.waitFor(t, ReasonBadToken)
	assert.Zero(t, pg.connections(), "a refused client costs the database nothing")

	// Giving the database password itself as the token does not work either.
	c = dialClient(t, addr, "klph", "appdb", realPassword)
	require.NotNil(t, c.authError)
}

func TestTooManyWrongTokensEndTheSession(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, rep := newAdapter(t, pg.addr(), func(c *Config) { c.MaxAuthFailures = 2 })
	addr := serveAdapter(t, srv)

	for range 2 {
		require.NotNil(t, dialClient(t, addr, "klph", "d", "wrong").authError)
	}
	c := dialClient(t, addr, "klph", "d", sessionToken)
	require.NotNil(t, c.authError, "the right token is refused once the session has been guessed at")
	assert.Equal(t, "28000", c.authError.code)
	rep.waitFor(t, ReasonRefused)
	assert.Zero(t, pg.connections())
}

func TestUpstreamRefusalIsReportedWithoutDetail(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, "a-different-password", nil)
	srv, rep := newAdapter(t, pg.addr(), nil)
	addr := serveAdapter(t, srv)

	c := dialClient(t, addr, "klph", "appdb", sessionToken)
	require.NotNil(t, c.authError)
	assert.Equal(t, "08006", c.authError.code)
	assert.NotContains(t, c.authError.msg, realPassword)
	assert.NotContains(t, c.authError.msg, "a-different-password")
	rep.waitFor(t, ReasonUpstreamFailed)
}

func TestPasswordSourceFailureIsAnUpstreamFailure(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, rep := newAdapter(t, pg.addr(), func(c *Config) {
		c.Password = func(context.Context) ([]byte, error) { return nil, errors.New("vault locked") }
	})
	c := dialClient(t, serveAdapter(t, srv), "klph", "d", sessionToken)
	require.NotNil(t, c.authError)
	assert.Equal(t, "08006", c.authError.code)
	rep.waitFor(t, ReasonUpstreamFailed)
}

func TestUnreachableUpstream(t *testing.T) {
	srv, rep := newAdapter(t, "127.0.0.1:1", nil)
	c := dialClient(t, serveAdapter(t, srv), "klph", "d", sessionToken)
	require.NotNil(t, c.authError)
	rep.waitFor(t, ReasonUpstreamFailed)
}

func TestUpstreamTLSIsVerifiedAndRequired(t *testing.T) {
	cert := selfSigned(t, "db.example.test")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	pg := startFakePG(t, modeScram, realUser, realPassword, &tls.Config{Certificates: []tls.Certificate{cert}})

	t.Run("verified", func(t *testing.T) {
		srv, rep := newAdapter(t, pg.addr(), func(c *Config) {
			c.PlainUpstream = false
			c.TLS = &tls.Config{RootCAs: pool, ServerName: "db.example.test"}
		})
		c := dialClient(t, serveAdapter(t, srv), "klph", "appdb", sessionToken)
		require.Nil(t, c.authError)
		assert.Equal(t, realUser+"@appdb", c.query(t, "select 1"))
		rep.waitFor(t, ReasonConnected)
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		srv, rep := newAdapter(t, pg.addr(), func(c *Config) {
			c.PlainUpstream = false
			c.TLS = &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "db.example.test"}
		})
		c := dialClient(t, serveAdapter(t, srv), "klph", "appdb", sessionToken)
		require.NotNil(t, c.authError)
		rep.waitFor(t, ReasonUpstreamFailed)
	})

	t.Run("wrong host name", func(t *testing.T) {
		srv, rep := newAdapter(t, pg.addr(), func(c *Config) {
			c.PlainUpstream = false
			c.TLS = &tls.Config{RootCAs: pool, ServerName: "other.example.test"}
		})
		c := dialClient(t, serveAdapter(t, srv), "klph", "appdb", sessionToken)
		require.NotNil(t, c.authError)
		rep.waitFor(t, ReasonUpstreamFailed)
	})

	t.Run("a database without TLS is refused", func(t *testing.T) {
		plain := startFakePG(t, modeScram, realUser, realPassword, nil)
		srv, rep := newAdapter(t, plain.addr(), func(c *Config) { c.PlainUpstream = false })
		c := dialClient(t, serveAdapter(t, srv), "klph", "appdb", sessionToken)
		require.NotNil(t, c.authError)
		rep.waitFor(t, ReasonUpstreamFailed)
		assert.Empty(t, plain.seenStartups(), "no credential is offered over a connection without TLS")
	})
}

func TestCancelRequestsAreForwardedOnlyForBackendsOfThisSession(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, rep := newAdapter(t, pg.addr(), nil)
	addr := serveAdapter(t, srv)

	c := dialClient(t, addr, "klph", "appdb", sessionToken)
	require.Nil(t, c.authError)
	assert.Equal(t, [2]uint32{4242, 777}, c.key)

	cancel := func(pid, key uint32) {
		conn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		pkt := make([]byte, 16)
		binary.BigEndian.PutUint32(pkt, 16)
		binary.BigEndian.PutUint32(pkt[4:], codeCancel)
		binary.BigEndian.PutUint32(pkt[8:], pid)
		binary.BigEndian.PutUint32(pkt[12:], key)
		_, err = conn.Write(pkt)
		require.NoError(t, err)
		buf := make([]byte, 1)
		_, _ = conn.Read(buf) // the adapter closes the connection when it is done
	}
	cancel(1, 2)
	assert.Empty(t, pg.seenCancels(), "a key this session never handed out is dropped")
	cancel(4242, 777)
	rep.waitFor(t, ReasonCancel)
	require.Len(t, pg.seenCancels(), 1)
	assert.Equal(t, []byte{0, 0, 0x10, 0x92, 0, 0, 0x03, 0x09}, pg.seenCancels()[0])
}

func TestReplicationConnectionsAreRefused(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, rep := newAdapter(t, pg.addr(), nil)
	c := dialClient(t, serveAdapter(t, srv), "klph", "d", sessionToken, "replication", "database")
	require.NotNil(t, c.authError)
	assert.Equal(t, "0A000", c.authError.code)
	rep.waitFor(t, ReasonRefused)
	assert.Zero(t, pg.connections())
}

func TestMalformedAndUnsupportedStartupsAreClosed(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, _ := newAdapter(t, pg.addr(), nil)
	addr := serveAdapter(t, srv)

	send := func(b []byte) []byte {
		conn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write(b)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		out, _ := io.ReadAll(conn)
		return out
	}
	packet := func(code uint32, body []byte) []byte {
		b := make([]byte, 8, 8+len(body))
		binary.BigEndian.PutUint32(b, uint32(8+len(body)))
		binary.BigEndian.PutUint32(b[4:], code)
		return append(b, body...)
	}

	assert.Contains(t, string(send(packet(protocolV3, []byte("user\x00x")))), "invalid startup message")
	assert.Contains(t, string(send(packet(1234, nil))), "unsupported protocol")
	assert.Empty(t, send([]byte{0, 0, 0, 3, 0, 0, 0}), "a length below the minimum is closed")
	assert.Empty(t, send(packet(codeCancel, []byte{1, 2})), "a short cancel request is dropped")
	assert.Zero(t, pg.connections())

	// Repeated SSL requests do not loop forever.
	req := append(append(packet(codeSSLRequest, nil), packet(codeGSSRequest, nil)...), packet(codeSSLRequest, nil)...)
	assert.Equal(t, []byte("NNN"), send(append(req, packet(codeSSLRequest, nil)...)))
}

func TestAClientThatSendsGarbageInsteadOfAPasswordIsDropped(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, _ := newAdapter(t, pg.addr(), nil)
	addr := serveAdapter(t, srv)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write(encodeStartup([]string{"user"}, map[string]string{"user": "x"}))
	require.NoError(t, err)
	var head [9]byte
	_, err = conn.Read(head[:])
	require.NoError(t, err)
	require.NoError(t, writeMessage(conn, 'Q', []byte("select 1\x00")))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	assert.Zero(t, n)
	assert.Zero(t, pg.connections())
}

func TestNewValidatesTheSession(t *testing.T) {
	ok := Config{Token: "t", Target: "db.example:5432", User: "u", Password: func(context.Context) ([]byte, error) { return nil, nil }}
	_, err := New(ok)
	require.NoError(t, err)
	for name, mutate := range map[string]func(*Config){
		"no token":    func(c *Config) { c.Token = "" },
		"no target":   func(c *Config) { c.Target = "" },
		"no user":     func(c *Config) { c.User = "" },
		"no password": func(c *Config) { c.Password = nil },
		"no port":     func(c *Config) { c.Target = "db.example" },
	} {
		cfg := ok
		mutate(&cfg)
		_, err := New(cfg)
		assert.Error(t, err, name)
	}
}

func TestServeStopsWhenTheContextEnds(t *testing.T) {
	pg := startFakePG(t, modeScram, realUser, realPassword, nil)
	srv, _ := newAdapter(t, pg.addr(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	near, far := net.Pipe()
	done := make(chan struct{})
	go func() { srv.Serve(ctx, far); close(done) }()

	go func() {
		// A real client: it runs through the handshake on the pipe.
		_, _ = near.Write(encodeStartup([]string{"user"}, map[string]string{"user": "x"}))
		buf := make([]byte, 9)
		_, _ = near.Read(buf)
		_ = writeMessage(near, 'p', append([]byte(sessionToken), 0))
		drain := make([]byte, 4096)
		for {
			if _, err := near.Read(drain); err != nil {
				return
			}
		}
	}()
	require.Eventually(t, func() bool { return pg.connections() == 1 }, 5*time.Second, 5*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its context ended")
	}
}

func TestWireHelpers(t *testing.T) {
	_, err := parseStartup([]byte("user\x00a\x00\x00"))
	require.NoError(t, err)
	for _, bad := range [][]byte{nil, []byte("user\x00a\x00"), []byte("\x00a\x00\x00"), []byte("a\x00\x00")} {
		_, err := parseStartup(bad)
		assert.Error(t, err, "%q", bad)
	}

	assert.True(t, hasMechanism(append([]byte("SCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00"), 0), scramMechanism))
	assert.False(t, hasMechanism([]byte("SCRAM-SHA-256-PLUS\x00\x00"), scramMechanism))
	assert.False(t, hasMechanism([]byte("SCRAM-SHA-256"), scramMechanism), "an unterminated name is not a mechanism")

	e := parseError(errorBody("28P01", "nope"))
	assert.Equal(t, "28P01", e.code)
	assert.Contains(t, e.Error(), "nope")

	_, err = readMessage(strings.NewReader("Q\x00\x00\x00\x02"))
	assert.ErrorIs(t, err, errProtocol)
	_, err = readMessage(strings.NewReader("Q\x7f\xff\xff\xff"))
	assert.ErrorIs(t, err, errProtocol)
	_, _, err = readStartup(strings.NewReader("\x00\x00\x00\x03\x00\x00\x00\x00"))
	assert.ErrorIs(t, err, errStartup)
}

func TestSCRAMRejectsABadServer(t *testing.T) {
	newClient := func() *scramClient {
		c, err := newSCRAMClient("pw")
		require.NoError(t, err)
		return c
	}
	c := newClient()
	for name, serverFirst := range map[string]string{
		"foreign nonce":    "r=other,s=c2FsdA==,i=4096",
		"nonce not longer": "r=" + c.nonce + ",s=c2FsdA==,i=4096",
		"bad salt":         "r=" + c.nonce + "x,s=!!,i=4096",
		"zero iterations":  "r=" + c.nonce + "x,s=c2FsdA==,i=0",
		"huge iterations":  "r=" + c.nonce + "x,s=c2FsdA==,i=99999999",
	} {
		_, err := c.final([]byte(serverFirst))
		assert.ErrorIs(t, err, errScram, name)
	}

	_, err := c.final([]byte("r=" + c.nonce + "x,s=c2FsdA==,i=4096"))
	require.NoError(t, err)
	assert.ErrorIs(t, c.verify([]byte("v=AAAA")), errScram, "a server that does not know the password is rejected")
	assert.ErrorIs(t, c.verify([]byte("e=invalid-proof")), errScram)
	assert.ErrorIs(t, c.verify([]byte("v=%%%")), errScram)
}

func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
