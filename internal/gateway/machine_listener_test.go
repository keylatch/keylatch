package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/machinecert"
)

type machineWorld struct {
	caKey   ed25519.PrivateKey
	ca      *x509.Certificate
	pool    *x509.CertPool
	server  tls.Certificate
	revoked map[string]bool
	calls   []MachineCall
	refused []string
	mu      sync.Mutex
	failure error
}

func newMachineWorld(t *testing.T) *machineWorld {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca, _, err := machinecert.CA(caKey)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	spub, skey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sder, err := machinecert.IssueServer(ca, caKey, spub, []string{"127.0.0.1", "localhost"}, time.Now(), time.Now().Add(time.Hour))
	require.NoError(t, err)
	return &machineWorld{caKey: caKey, ca: ca, pool: pool, revoked: map[string]bool{},
		server: tls.Certificate{Certificate: [][]byte{sder}, PrivateKey: skey}}
}

func (w *machineWorld) client(t *testing.T, name, domain string, caps []string, ttl time.Duration) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, _, err := machinecert.IssueClient(w.ca, w.caKey, pub, machinecert.Claims{Name: name, Domain: domain, Caps: caps, NotAfter: time.Now().Add(ttl)}, time.Now())
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (w *machineWorld) Authenticate(cert *x509.Certificate) (MachinePrincipal, error) {
	c, err := machinecert.ClaimsOf(cert)
	if err != nil {
		return MachinePrincipal{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.revoked[cert.SerialNumber.String()] {
		return MachinePrincipal{}, ErrMachineRevoked
	}
	return MachinePrincipal{Name: c.Name, Domain: c.Domain, Caps: c.Caps, Serial: cert.SerialNumber.String()}, nil
}

func (w *machineWorld) Call(_ context.Context, p MachinePrincipal, c MachineCall) (MachineCallResult, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, c)
	if w.failure != nil {
		return MachineCallResult{}, w.failure
	}
	return MachineCallResult{Status: 200, Body: []byte(`{"domain":"` + p.Domain + `"}`)}, nil
}

func (w *machineWorld) Refused(_ context.Context, _ *MachinePrincipal, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refused = append(w.refused, reason)
}

func (w *machineWorld) start(t *testing.T) (*httptest.Server, *MachineListener) {
	t.Helper()
	l, err := NewMachineListener(MachineListenerConfig{Addr: "127.0.0.1:8443", ClientCAs: w.pool, ServerCert: w.server, Backend: w})
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(l.Handler())
	srv.TLS = l.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, l
}

func (w *machineWorld) httpClient(cert *tls.Certificate, maxVersion uint16) *http.Client {
	cfg := &tls.Config{RootCAs: w.pool, ServerName: "localhost", MaxVersion: maxVersion}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func post(t *testing.T, c *http.Client, url string, body any) (*http.Response, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := c.Post(url+"/v1/call", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestMachineListenerMTLS(t *testing.T) {
	w := newMachineWorld(t)
	srv, _ := w.start(t)
	cert := w.client(t, "ci-1", "ci", []string{"call"}, time.Hour)

	resp, out := post(t, w.httpClient(&cert, 0), srv.URL, MachineCall{Connection: "openai", Action: "list-models"})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, float64(200), out["status_code"])
	assert.Equal(t, 1, len(w.calls))
	assert.Equal(t, uint16(tls.VersionTLS13), resp.TLS.Version)

	// No client certificate: the handshake fails.
	_, err := w.httpClient(nil, 0).Post(srv.URL+"/v1/call", "application/json", strings.NewReader("{}"))
	assert.Error(t, err)

	// A certificate from another CA is refused.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	otherCA, _, _ := machinecert.CA(otherKey)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _, err := machinecert.IssueClient(otherCA, otherKey, pub, machinecert.Claims{Name: "evil", Domain: "ci", Caps: []string{"call"}, NotAfter: time.Now().Add(time.Hour)}, time.Now())
	require.NoError(t, err)
	foreign := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	_, err = w.httpClient(&foreign, 0).Post(srv.URL+"/v1/call", "application/json", strings.NewReader("{}"))
	assert.Error(t, err, "a certificate the machine CA did not sign")

	// TLS 1.2 is refused.
	_, err = w.httpClient(&cert, tls.VersionTLS12).Post(srv.URL+"/v1/call", "application/json", strings.NewReader("{}"))
	assert.Error(t, err)

	// An expired certificate is refused at the handshake.
	expired := w.client(t, "old", "ci", []string{"call"}, -time.Minute)
	_, err = w.httpClient(&expired, 0).Post(srv.URL+"/v1/call", "application/json", strings.NewReader("{}"))
	assert.Error(t, err)

	assert.Equal(t, 1, len(w.calls), "only the valid call reached the backend")
}

func TestMachineRevocationIsCheckedPerRequest(t *testing.T) {
	w := newMachineWorld(t)
	srv, _ := w.start(t)
	cert := w.client(t, "ci-1", "ci", []string{"call"}, time.Hour)
	client := w.httpClient(&cert, 0)

	resp, _ := post(t, client, srv.URL, MachineCall{Connection: "openai", Action: "list-models"})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	w.mu.Lock()
	w.revoked[parsed.SerialNumber.String()] = true
	w.mu.Unlock()

	// The same keep-alive connection, the next request.
	resp, _ = post(t, client, srv.URL, MachineCall{Connection: "openai", Action: "list-models"})
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, 1, len(w.calls))
	assert.NotEmpty(t, w.refused)
}

func TestCrossDomainRefused(t *testing.T) {
	w := newMachineWorld(t)
	srv, _ := w.start(t)
	cert := w.client(t, "ci-1", "ci", []string{"call"}, time.Hour)
	client := w.httpClient(&cert, 0)

	resp, out := post(t, client, srv.URL, MachineCall{Connection: "openai", Action: "list-models", Namespace: "prod"})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "cross_domain", out["error"].(map[string]any)["code"])
	assert.Empty(t, w.calls, "a cross-domain call never reaches the backend")
	require.Len(t, w.refused, 1)
	assert.Contains(t, w.refused[0], "prod")

	// Naming its own domain is fine; so is naming none.
	for _, ns := range []string{"ci", ""} {
		resp, _ = post(t, client, srv.URL, MachineCall{Connection: "openai", Action: "list-models", Namespace: ns})
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// A certificate without the call capability is refused.
	noCaps := w.client(t, "mint-only", "ci", []string{"mint"}, time.Hour)
	resp, out = post(t, w.httpClient(&noCaps, 0), srv.URL, MachineCall{Connection: "openai", Action: "list-models"})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "capability", out["error"].(map[string]any)["code"])
}

func TestMachineListenerRejectsMalformedRequests(t *testing.T) {
	w := newMachineWorld(t)
	srv, _ := w.start(t)
	cert := w.client(t, "ci-1", "ci", []string{"call"}, time.Hour)
	client := w.httpClient(&cert, 0)
	for name, body := range map[string]string{
		"not json":        "{",
		"unknown field":   `{"connection":"a","action":"b","admin":true}`,
		"bad connection":  `{"connection":"../x","action":"b"}`,
		"missing action":  `{"connection":"a"}`,
		"huge connection": `{"connection":"` + strings.Repeat("a", 300) + `","action":"b"}`,
	} {
		resp, err := client.Post(srv.URL+"/v1/call", "application/json", strings.NewReader(body))
		require.NoError(t, err, name)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, name)
	}
	resp, err := client.Get(srv.URL + "/v1/call")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

	w.failure = ErrMachineNotFound
	resp2, _ := post(t, client, srv.URL, MachineCall{Connection: "a", Action: "b"})
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
	w.failure = errors.New("upstream timeout with a secret in it")
	resp2, out := post(t, client, srv.URL, MachineCall{Connection: "a", Action: "b"})
	assert.Equal(t, http.StatusBadGateway, resp2.StatusCode)
	assert.NotContains(t, out["error"].(map[string]any)["message"], "secret")
	w.failure = ErrMachineRevoked
	resp2, _ = post(t, client, srv.URL, MachineCall{Connection: "a", Action: "b"})
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestWildcardBindRefused(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8443", "[::]:8443", ":8443", "0:8443"} {
		assert.ErrorIs(t, ValidateMachineAddr(addr, false), ErrWildcardBind, addr)
		assert.NoError(t, ValidateMachineAddr(addr, true), addr)
	}
	for _, addr := range []string{"10.0.0.5:8443", "[fd00::1]:8443", "host.example:8443", "127.0.0.1:1"} {
		assert.NoError(t, ValidateMachineAddr(addr, false), addr)
	}
	for _, addr := range []string{"nope", "10.0.0.5", "10.0.0.5:0", "10.0.0.5:99999", "10.0.0.5:x"} {
		assert.Error(t, ValidateMachineAddr(addr, true), addr)
	}
	w := newMachineWorld(t)
	_, err := NewMachineListener(MachineListenerConfig{Addr: "0.0.0.0:8443", ClientCAs: w.pool, ServerCert: w.server, Backend: w})
	assert.ErrorIs(t, err, ErrWildcardBind)
	_, err = NewMachineListener(MachineListenerConfig{Addr: "127.0.0.1:8443"})
	assert.Error(t, err)
}

func TestMachineListenerServeAndStop(t *testing.T) {
	w := newMachineWorld(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	l, err := NewMachineListener(MachineListenerConfig{
		Addr: addr, ClientCAs: w.pool, ServerCert: w.server, Backend: w,
		Listen: func(string, string) (net.Listener, error) { return ln, nil },
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Serve(ctx) }()
	cert := w.client(t, "ci-1", "ci", []string{"call"}, time.Hour)
	resp, _ := post(t, w.httpClient(&cert, 0), "https://"+strings.Replace(addr, "127.0.0.1", "localhost", 1), MachineCall{Connection: "a", Action: "b"})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the listener did not stop")
	}

	bad := &MachineListener{cfg: MachineListenerConfig{Addr: "127.0.0.1:1", Listen: func(string, string) (net.Listener, error) { return nil, errors.New("in use") }}}
	assert.Error(t, bad.Serve(context.Background()))
}
