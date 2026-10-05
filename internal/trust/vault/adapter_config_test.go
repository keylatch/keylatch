package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/trust"
)

func TestNewRequiresAddr(t *testing.T) {
	_, err := New(Options{})
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "addr not set") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewCACertErrors(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(garbage, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"missing CA file", Options{Addr: "http://x", CACertPath: filepath.Join(dir, "nope.pem")}, "read CA cert"},
		{"unparseable CA", Options{Addr: "http://x", CACertPath: garbage}, "parse CA cert"},
		{"missing client cert", Options{Addr: "http://x", ClientCert: filepath.Join(dir, "c.pem"), ClientKey: filepath.Join(dir, "k.pem")}, "load client cert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts)
			if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestIdentityAndCapabilities(t *testing.T) {
	a, err := New(Options{Addr: "http://x", AuthMethod: "oidc", TransitKeyName: "kek"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != "vault:kek" || a.Type() != trust.RootVaultTransit {
		t.Fatalf("ID=%q Type=%q", a.ID(), a.Type())
	}
	for _, c := range []trust.Capability{trust.CapWrap, trust.CapSignChallenge, trust.CapAttestation} {
		if !a.Has(c) {
			t.Errorf("Has(%d) = false", c)
		}
	}
	for _, c := range []trust.Capability{trust.CapUserPresence, trust.CapHardwareBound, trust.CapMTLSClientAuth, trust.CapLaunchdSafe, trust.Capability(1 << 20)} {
		if a.Has(c) {
			t.Errorf("Has(%d) = true for oidc without mTLS", c)
		}
	}

	for _, m := range []string{"approle", "k8s"} {
		b, _ := New(Options{Addr: "http://x", AuthMethod: m})
		if !b.Has(trust.CapLaunchdSafe) {
			t.Errorf("%s should be launchd-safe", m)
		}
	}

	certPath, keyPath, _ := trWriteClientCert(t)
	m, err := New(Options{Addr: "http://x", AuthMethod: "mtls", ClientCert: certPath, ClientKey: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Has(trust.CapMTLSClientAuth) || !m.Has(trust.CapLaunchdSafe) {
		t.Fatal("mTLS adapter should report mTLS client auth and launchd safety")
	}
}

func TestUnsupportedOperations(t *testing.T) {
	a, _ := New(Options{Addr: "http://x"})
	ctx := context.Background()
	if err := a.Verify(ctx, nil, nil, nil); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("Verify: %v", err)
	}
	if _, err := a.RequirePresence(ctx, "why"); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("RequirePresence: %v", err)
	}
	if err := a.VerifyPresenceProof(ctx, trust.PresenceProof{}); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Errorf("VerifyPresenceProof: %v", err)
	}
	att, err := a.Attest(ctx)
	if err != nil || att.Format != "vault-token" {
		t.Errorf("Attest = %+v, %v", att, err)
	}
}

func TestAuthMethodSelection(t *testing.T) {
	ctx := context.Background()
	if _, err := authenticate(ctx, Options{AuthMethod: "oidc"}, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "interactive") {
		t.Errorf("oidc: %v", err)
	}
	if _, err := authenticate(ctx, Options{AuthMethod: "ldap"}, http.DefaultClient); err == nil || !strings.Contains(err.Error(), `unknown auth method "ldap"`) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		t.Skip("running inside kubernetes; SA token present")
	}
	if _, err := authenticate(ctx, Options{AuthMethod: "k8s"}, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "read SA token") {
		t.Errorf("k8s: %v", err)
	}
}

func TestRegisteredFactoryReadsExtra(t *testing.T) {
	r, err := trust.New(trust.RootSpec{
		Type:  trust.RootVaultTransit,
		Label: "corp",
		Extra: map[string]any{
			"addr":        "http://vault.invalid",
			"auth_method": "approle",
			"transit_key": "kek2",
			"namespace":   "ns",
		},
	})
	if err != nil {
		t.Fatalf("trust.New: %v", err)
	}
	a := r.(*Adapter)
	if a.ID() != "vault:kek2" || a.opts.Namespace != "ns" || a.opts.Label != "corp" || a.opts.AuthMethod != "approle" {
		t.Fatalf("opts = %+v", a.opts)
	}

	_, err = trust.New(trust.RootSpec{Type: trust.RootVaultTransit})
	if !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("missing extra: err = %v", err)
	}
}

func TestMTLSLoginOverTLS(t *testing.T) {
	certPath, keyPath, clientCert := trWriteClientCert(t)
	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCert)

	var sawClientCN string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/cert/login":
			if len(r.TLS.PeerCertificates) > 0 {
				sawClientCN = r.TLS.PeerCertificates[0].Subject.CommonName
			}
			_, _ = io.WriteString(w, `{"auth":{"client_token":"mtls-tok"}}`)
		case "/v1/transit/encrypt/kek":
			if r.Header.Get("X-Vault-Token") != "mtls-tok" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"ciphertext":"vault:v1:m"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientPool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := New(Options{
		Addr: srv.URL, AuthMethod: "mtls", TransitKeyName: "kek",
		CACertPath: caPath, ClientCert: certPath, ClientKey: keyPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := a.Wrap(context.Background(), []byte("k"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if string(out) != "vault:v1:m" || sawClientCN != "keylatch-test-client" {
		t.Fatalf("out=%q cn=%q", out, sawClientCN)
	}

	noCert, err := New(Options{Addr: srv.URL, AuthMethod: "mtls", TransitKeyName: "kek", CACertPath: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noCert.Wrap(context.Background(), []byte("k")); err == nil || !strings.Contains(err.Error(), "mtls auth") {
		t.Fatalf("login without client cert: err = %v", err)
	}
}

func TestJSONExtractString(t *testing.T) {
	cases := []struct {
		in, key, want string
	}{
		{`{"auth":{"client_token":"abc"}}`, "client_token", "abc"},
		{`{"x":1}`, "client_token", ""},
		{`{"client_token":"`, "client_token", ""},
		{`{"client_token":"unterminated`, "client_token", ""},
		{``, "k", ""},
	}
	for _, tc := range cases {
		if got := jsonExtractString([]byte(tc.in), tc.key); got != tc.want {
			t.Errorf("jsonExtractString(%q, %q) = %q, want %q", tc.in, tc.key, got, tc.want)
		}
	}
}

func TestSanitizeStripsControlAndTruncates(t *testing.T) {
	if got := sanitize([]byte("a\nb\x00c\xffd")); got != "abcd" {
		t.Fatalf("sanitize = %q", got)
	}
	if got := sanitize([]byte(strings.Repeat("z", 500))); len(got) != 200 {
		t.Fatalf("len = %d", len(got))
	}
}

func TestReadersDeliverAndZero(t *testing.T) {
	buf := []byte("secret-body")
	got, err := io.ReadAll(bytesReaderZero(buf))
	if err != nil || string(got) != "secret-body" {
		t.Fatalf("bytesReaderZero read %q, %v", got, err)
	}
	// The writer goroutine zeroes after Write returns; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for {
		zeroed := true
		for _, b := range buf {
			if b != 0 {
				zeroed = false
			}
		}
		if zeroed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("buffer not zeroed")
		}
		time.Sleep(time.Millisecond)
	}

	got, err = io.ReadAll(stringReader("plain"))
	if err != nil || string(got) != "plain" {
		t.Fatalf("stringReader read %q, %v", got, err)
	}
}

func trWriteClientCert(t *testing.T) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "keylatch-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC " + "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, cert
}
