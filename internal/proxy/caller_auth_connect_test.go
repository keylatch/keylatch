package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mxEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *mxEmitter) Emit(_ context.Context, e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *mxEmitter) reasons() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for _, e := range m.events {
		out = append(out, e.Extra["reason"].(string))
	}
	return out
}

type mxVault map[string][]byte

func (v mxVault) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	val, ok := v[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return append([]byte(nil), val...), backend.Meta{}, nil
}

func TestCallerAuth_RejectsBeforeAnyRoutingDecision(t *testing.T) {
	em := &mxEmitter{}
	srv := &Server{
		Token:        "session-token-value",
		Profile:      ProxyProfile{Hosts: []string{"allowed.example"}},
		AuditEmitter: em,
	}
	cases := map[string]string{
		"missing":      "",
		"wrong scheme": "Basic session-token-value",
		"wrong token":  "Bearer session-token-valuE",
		"prefix only":  "Bearer ",
	}
	for name, header := range cases {
		for _, method := range []string{http.MethodGet, http.MethodConnect} {
			req := httptest.NewRequest(method, "http://allowed.example/v1", nil)
			req.Host = "allowed.example"
			if header != "" {
				req.Header.Set("Proxy-Authorization", header)
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s", name, method)
			assert.NotContains(t, rec.Body.String(), "host_not_allowed", "unauthenticated callers learn nothing about the profile")
		}
	}
	for _, r := range em.reasons() {
		assert.Equal(t, "proxy_caller_unauthenticated", r)
	}

	// The right token proceeds to the normal allowlist decision.
	req := httptest.NewRequest(http.MethodGet, "http://denied.example/v1", nil)
	req.Host = "denied.example"
	req.Header.Set("Proxy-Authorization", "Bearer session-token-value")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "host_not_allowed")
}

func TestEnsureToken(t *testing.T) {
	preset := &Server{Token: "fixed"}
	tok, err := preset.EnsureToken()
	require.NoError(t, err)
	assert.Equal(t, "fixed", tok)

	s := &Server{}
	tok, err = s.EnsureToken()
	require.NoError(t, err)
	assert.Regexp(t, `^[0-9a-f]{64}$`, tok)
	again, err := s.EnsureToken()
	require.NoError(t, err)
	assert.Equal(t, tok, again, "token is minted once per server")
}

func TestServe_RefusesNonLoopbackBind(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "10.0.0.1:7879", "example.com:7879"} {
		s := &Server{Addr: addr}
		err := s.Serve(context.Background())
		require.Error(t, err, addr)
		assert.Contains(t, err.Error(), "loopback-only")
		assert.Empty(t, s.Token, "no token is minted for a refused bind")
	}
	for addr, want := range map[string]bool{"localhost:1": true, "[::1]:1": true, "::1": true, "127.0.0.1": true, "[::1]": true, "": false} {
		assert.Equal(t, want, isLoopbackAddr(addr), addr)
	}
}

func mxCA(t *testing.T) (*tlsCA, *x509.CertPool) {
	t.Helper()
	cert, key, err := LoadOrCreateCA(newMemKeyring(), "mx-ca")
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return newTLSCA(cert, key), pool
}

func TestCONNECT_TLSInterceptionInjectsVaultCredential(t *testing.T) {
	type seen struct{ auth, proxyAuth, path string }
	got := make(chan seen, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Header.Get("Authorization"), r.Header.Get("Proxy-Authorization"), r.URL.Path}
		w.Header().Set("X-Upstream", "yes")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	require.NoError(t, err)

	ca, roots := mxCA(t)
	cred := "vault-" + strings.Repeat("c", 16)
	srv := &Server{
		Token: "tok",
		CA:    ca,
		Vault: mxVault{"providers/key": []byte(cred)},
		Profile: ProxyProfile{
			Hosts:  []string{"localhost"},
			Routes: []ProxyRoute{{Path: "/v1/", AuthInjection: AuthInjection{Placement: "header", Name: "Authorization", Value: "{{ secret.providers/key }}"}}},
		},
	}
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	srv.clientOnce.Do(func() {
		srv.client = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: upstreamPool, ServerName: "example.com", MinVersion: tls.VersionTLS12},
		}}
	})

	front := httptest.NewServer(srv)
	defer front.Close()
	proxyURL, err := url.Parse(front.URL)
	require.NoError(t, err)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:              http.ProxyURL(proxyURL),
		ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer tok"}},
		TLSClientConfig:    &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}

	req, err := http.NewRequest(http.MethodGet, "https://localhost:"+port+"/v1/models", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer caller-supplied")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"ok":true}`, string(body))
	assert.Equal(t, "yes", resp.Header.Get("X-Upstream"))
	require.NotNil(t, resp.TLS)
	assert.Equal(t, "localhost", resp.TLS.PeerCertificates[0].Subject.CommonName, "client sees the minted leaf")

	s := <-got
	assert.Equal(t, cred, s.auth, "caller Authorization is replaced by the vault credential")
	assert.Empty(t, s.proxyAuth)
	assert.Equal(t, "/v1/models", s.path)
}

func mxConnect(t *testing.T, proxyAddr, target, token string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	require.NoError(t, err)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\nProxy-Authorization: Bearer "+token+"\r\n\r\n")
	require.NoError(t, err)
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, line, "200 Connection established")
	// The proxy writes only the status line and a blank line before the tunnel.
	return conn
}

func TestCONNECT_WithoutCATunnelsRawTCP(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer echo.Close()
	go func() {
		c, aerr := echo.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	_, port, _ := net.SplitHostPort(echo.Addr().String())

	srv := &Server{Token: "tok", Profile: ProxyProfile{Hosts: []string{"localhost"}}}
	front := httptest.NewServer(srv)
	defer front.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(front.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(conn, "CONNECT localhost:"+port+" HTTP/1.1\r\nHost: localhost:"+port+"\r\nProxy-Authorization: Bearer tok\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, line, "200 Connection established")
	_, err = br.ReadString('\n')
	require.NoError(t, err)

	_, err = io.WriteString(conn, "ping\n")
	require.NoError(t, err)
	reply, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "ping\n", reply)
}

func TestCONNECT_UnreachableUpstreamAndBadHandshake(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, deadPort, _ := net.SplitHostPort(closed.Addr().String())
	require.NoError(t, closed.Close())

	ca, _ := mxCA(t)
	for name, s := range map[string]*Server{
		"raw tunnel": {Token: "tok", Profile: ProxyProfile{Hosts: []string{"localhost"}}},
		"tls":        {Token: "tok", CA: ca, Profile: ProxyProfile{Hosts: []string{"localhost"}}},
	} {
		t.Run(name, func(t *testing.T) {
			front := httptest.NewServer(s)
			defer front.Close()
			conn := mxConnect(t, strings.TrimPrefix(front.URL, "http://"), "localhost:"+deadPort, "tok")
			defer conn.Close()
			// Not a TLS ClientHello: the handshake fails and the proxy closes the tunnel.
			_, _ = io.WriteString(conn, "\r\nnot tls at all\r\n\r\n")
			buf := make([]byte, 64)
			_, rerr := conn.Read(buf)
			assert.Error(t, rerr, "proxy must close the tunnel")
		})
	}
}

func TestRouteHandler_UpstreamFailureAndNoCredential(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	host := strings.TrimPrefix(closed.URL, "http://")
	closed.Close()

	srv := &Server{Profile: ProxyProfile{
		Hosts:  []string{host},
		Routes: []ProxyRoute{{Path: "/", AuthInjection: AuthInjection{Value: "literal-not-a-template"}}},
	}, Vault: mxVault{}}
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/x", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "upstream_error")

	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization") + "|" + r.Header.Get("X-Keylatch-Internal")
		w.WriteHeader(http.StatusTeapot)
	}))
	defer up.Close()
	upHost := strings.TrimPrefix(up.URL, "http://")
	srv = &Server{Profile: ProxyProfile{Hosts: []string{upHost}, Routes: []ProxyRoute{{Method: http.MethodGet, Path: "/"}}}}
	req = httptest.NewRequest(http.MethodGet, "http://"+upHost+"/x", nil)
	req.Host = upHost
	req.Header.Set("Authorization", "Bearer caller")
	req.Header.Set("X-Keylatch-Internal", "secret-hint")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "|", gotAuth, "caller auth and internal headers are never forwarded")

	req = httptest.NewRequest(http.MethodPost, "http://"+upHost+"/x", nil)
	req.Host = upHost
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, "method mismatch means no route")
}

func TestHostAllowed_PortNormalisation(t *testing.T) {
	s := &Server{Profile: ProxyProfile{Hosts: []string{"api.example.com:443", "other.example"}}}
	assert.True(t, s.hostAllowed("api.example.com"))
	assert.True(t, s.hostAllowed("other.example"))
	assert.False(t, s.hostAllowed("evil.example"))
	assert.False(t, (&Server{}).hostAllowed("api.example.com"), "empty allowlist denies everything")
}

func TestCertForHost_ExpiredCacheAndWrongKeyType(t *testing.T) {
	ca, _ := mxCA(t)
	first, err := ca.CertForHost("h.example")
	require.NoError(t, err)
	first.Leaf.NotAfter = time.Now().Add(-time.Minute)
	second, err := ca.CertForHost("h.example")
	require.NoError(t, err)
	assert.NotSame(t, first, second, "expired cached leaf is re-minted")

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	bad := newTLSCA(ca.cert, edKey)
	_, err = bad.CertForHost("h.example")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be *ecdsa.PrivateKey")
}

type mxBadKeyring struct {
	stored []byte
	setErr error
}

func (k *mxBadKeyring) Get(string) ([]byte, error) { return k.stored, nil }
func (k *mxBadKeyring) Set(string, []byte) error   { return k.setErr }

func TestLoadOrCreateCA_KeyringFailures(t *testing.T) {
	_, _, err := LoadOrCreateCA(&mxBadKeyring{stored: []byte("garbage")}, "k")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse stored private key")

	_, _, err = LoadOrCreateCA(&mxBadKeyring{setErr: errors.New("locked")}, "k")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store private key in keyring")

	cert, key, err := LoadOrCreateCA(&mxBadKeyring{}, "k")
	require.NoError(t, err, "an empty stored value means generate a new key")
	assert.True(t, cert.IsCA)
	_, isEC := key.(*ecdsa.PrivateKey)
	assert.True(t, isEC)
}

type mxFailWriter struct{ after int }

func (w *mxFailWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("broken pipe")
	}
	w.after--
	return len(p), nil
}

func TestBufferedResponseWriter_UnknownStatusAndWriteErrors(t *testing.T) {
	rw := newBufferedResponseWriter()
	rw.WriteHeader(799)
	rw.Header().Set("X-A", "1")
	_, _ = rw.Write([]byte("body"))
	var sb strings.Builder
	require.NoError(t, rw.writeResponseTo(&sb))
	assert.True(t, strings.HasPrefix(sb.String(), "HTTP/1.1 799 Unknown\r\n"))
	assert.True(t, strings.HasSuffix(sb.String(), "Content-Length: 4\r\n\r\nbody"))

	for after := 0; after < 3; after++ {
		assert.Error(t, rw.writeResponseTo(&mxFailWriter{after: after}), "failure after %d writes", after)
	}
}
