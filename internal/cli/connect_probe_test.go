package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/registry"
)

const probeSecret = "billing-live-value-0123456789"

func hostCert(t *testing.T, name string) tls.Certificate {
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

// billingUpstream stands in for api.billing.example: it accepts only the real
// value and records what it was sent.
func billingUpstream(t *testing.T) (*[]string, func()) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []string
	)
	cert := hostCert(t, "api.billing.example")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+probeSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	prev := probeUpstream
	probeUpstream = placeholder.Upstream{
		Roots: pool,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
		Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil },
	}
	return &seen, func() { probeUpstream = prev; srv.Close() }
}

func probeInput(url string, expect int) customConnectInput {
	in := customInputFor("api.billing.example:443")
	in.Fields = map[string][]byte{"api_key": []byte(probeSecret)}
	in.TestURL, in.Expect = url, expect
	return in
}

func TestConnectTestURLSendsOnlyAPlaceholderAndTheProxyAddsTheRealValue(t *testing.T) {
	seen, stop := billingUpstream(t)
	defer stop()
	st, em := newMapStore(), &recordingEmitter{}
	var out bytes.Buffer

	require.NoError(t, connectCustom(context.Background(), &out, st, "billing-internal", probeInput("https://api.billing.example/v1/ping", 200), connections.CallerHuman, em))

	assert.Equal(t, []string{"Bearer " + probeSecret}, *seen, "the upstream saw the real value")
	assert.Contains(t, out.String(), "returned 200 through the placeholder proxy")
	assert.NotContains(t, out.String(), probeSecret)
}

func TestConnectTestURLReportsAStatusThatIsNotTheExpectedOne(t *testing.T) {
	_, stop := billingUpstream(t)
	defer stop()
	st, em := newMapStore(), &recordingEmitter{}
	in := probeInput("https://api.billing.example/v1/ping", 200)
	in.Fields = map[string][]byte{"api_key": []byte("a-wrong-key-0123456789")}

	err := connectCustom(context.Background(), &bytes.Buffer{}, st, "billing-internal", in, connections.CallerHuman, em)
	requireExitCode(t, err, exitcode.OperationFailed)
	assert.Contains(t, err.Error(), "returned 401, expected 200")

	st2 := newMapStore()
	in2 := probeInput("https://api.billing.example/v1/ping", 401)
	in2.Fields = map[string][]byte{"api_key": []byte("a-wrong-key-0123456789")}
	require.NoError(t, connectCustom(context.Background(), &bytes.Buffer{}, st2, "billing-internal", in2, connections.CallerHuman, em), "--expect 401 accepts the refusal")
}

func TestConnectTestURLOutsideTheHostsIsRejectedBeforeAnythingIsSaved(t *testing.T) {
	st, em := newMapStore(), &recordingEmitter{}
	for _, u := range []string{"https://evil.example/ping", "https://api.billing.example:8443/ping", "http://api.billing.example/ping", "https://user:pw@api.billing.example/ping"} {
		err := connectCustom(context.Background(), &bytes.Buffer{}, st, "billing-internal", probeInput(u, 200), connections.CallerHuman, em)
		requireExitCode(t, err, exitcode.UserError)
	}
	assert.Empty(t, st.data, "a refused test URL saves no binding")
}

func TestConnectTestURLIsHumanOnly(t *testing.T) {
	st, em := newMapStore(), &recordingEmitter{}
	err := connectCustom(context.Background(), &bytes.Buffer{}, st, "billing-internal", probeInput("https://api.billing.example/ping", 200), connections.CallerAgent, em)
	requireExitCode(t, err, exitcode.SecurityBlock)
	assert.Empty(t, st.data)
}

func TestConnectTestURLNeedsTheAuditLog(t *testing.T) {
	_, stop := billingUpstream(t)
	defer stop()
	err := connectCustom(context.Background(), &bytes.Buffer{}, newMapStore(), "billing-internal", probeInput("https://api.billing.example/ping", 200), connections.CallerHuman, nil)
	requireExitCode(t, err, exitcode.OperationFailed)
	assert.Contains(t, err.Error(), "audit log")
}

func TestConnectTestURLUsesTheProbeSeam(t *testing.T) {
	in := probeInput("https://api.billing.example/ping", 204)
	in.Probe = func(_ context.Context, _ connections.Store, _ audit.Emitter, ns, name, url string) (int, error) {
		assert.Equal(t, "billing-internal", name)
		assert.Equal(t, "https://api.billing.example/ping", url)
		return 204, nil
	}
	var out bytes.Buffer
	require.NoError(t, connectCustom(context.Background(), &out, newMapStore(), "billing-internal", in, connections.CallerHuman, &recordingEmitter{}))
	assert.Contains(t, out.String(), "returned 204")
}

func TestApplyPlaceholderFollowsTheBindingsSlots(t *testing.T) {
	b := registry.Binding{Slots: []registry.Slot{
		{Field: "token", In: registry.SlotHeader, Name: "X-Api-Key", Hosts: []string{"a.example:443"}},
		{Field: "token", In: registry.SlotQuery, Name: "key", Hosts: []string{"a.example:443"}},
		{Field: "user", In: registry.SlotBasic, Part: registry.BasicUser, Hosts: []string{"a.example:443"}},
		{Field: "pass", In: registry.SlotBasic, Part: registry.BasicPassword, Hosts: []string{"a.example:443"}},
	}}
	req := httptest.NewRequest(http.MethodGet, "https://a.example/x", nil)
	require.NoError(t, applyPlaceholder(req, b, map[string]string{"token": "T", "user": "U", "pass": "P"}))
	assert.Equal(t, "T", req.Header.Get("X-Api-Key"))
	assert.Equal(t, "key=T", req.URL.RawQuery)
	u, p, ok := req.BasicAuth()
	assert.True(t, ok)
	assert.Equal(t, "U", u)
	assert.Equal(t, "P", p)

	other := httptest.NewRequest(http.MethodGet, "https://b.example/x", nil)
	err := applyPlaceholder(other, b, map[string]string{"token": "T"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "no slot"))
}
