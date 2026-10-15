//go:build !windows

package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/placeholder"
)

const realStripeKey = "sk_test_REALKEYVALUE0123456789abcdefgh"

type recordingAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingAudit) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingAudit) reasons() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		if e.Action == audit.ActionProxySession {
			out = append(out, fmt.Sprint(e.Extra["reason"]))
		}
	}
	return out
}

type fixedResolver map[string]string

func (f fixedResolver) Resolve(_ context.Context, _, field string) ([]byte, error) {
	return []byte(f[field]), nil
}

func startPlaceholderDaemon(t *testing.T) (env map[string]string, auth *recordingAudit, seenAuth chan string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.stripe.com"}, DNSNames: []string{"api.stripe.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	seenAuth = make(chan string, 8)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "balance-ok")
	}))
	up.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	up.StartTLS()
	t.Cleanup(up.Close)

	auth = &recordingAudit{}
	mgr, err := placeholder.NewManager(placeholder.Config{
		Resolver: fixedResolver{"secret_key": realStripeKey},
		Audit:    auth,
		Upstream: placeholder.Upstream{Roots: pool, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, up.Listener.Addr().String())
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)

	dir, err := os.MkdirTemp("/tmp", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := dir + "/s/k.sock"
	env = map[string]string{"KEYLATCH_CONFIG_DIR": dir + "/state", "KEYLATCH_SOCKET": socket}
	startServer(t, env, Config{Env: lookupOf(env), Binary: "/bin/true", Placeholders: mgr})
	return env, auth, seenAuth
}

func startServer(t *testing.T, env map[string]string, cfg Config) {
	t.Helper()
	ln, err := Listen(env["KEYLATCH_SOCKET"])
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = NewServer(cfg).Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// TestHelperChild is the process `run` starts in the tests below. It reports
// its view of the credential and makes one HTTPS request the way a tool that
// reads its key from the environment would.
func TestHelperChild(t *testing.T) {
	if os.Getenv("HELPER_CHILD") != "1" {
		return
	}
	key := os.Getenv("STRIPE_SECRET_KEY")
	fmt.Printf("key=%s\n", key)
	fmt.Printf("proxy=%t ca=%t node=%s\n", os.Getenv("HTTPS_PROXY") != "", os.Getenv("SSL_CERT_FILE") != "", os.Getenv("NODE_USE_ENV_PROXY"))
	if os.Getenv("HELPER_NO_REQUEST") == "" {
		req, _ := http.NewRequest("GET", "https://api.stripe.com/v1/balance", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			fmt.Printf("request: %v\n", err)
			os.Exit(3)
		}
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("status=%d body=%s\n", resp.StatusCode, body)
	}
	os.Exit(0)
}

func TestRunTierD3SubstitutesWithoutTheKeyInTheChild(t *testing.T) {
	env, auth, seen := startPlaceholderDaemon(t)
	t.Setenv("HELPER_CHILD", "1")
	t.Setenv("STRIPE_SECRET_KEY", "ambient-key-must-be-replaced")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("SSL_CERT_DIR", "")

	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(env),
		[]string{"run", "--tier", "D3", "stripe", "--", os.Args[0], "-test.run=^TestHelperChild$"}, IO{Out: &out, ErrOut: &errOut})
	if !handled || code != 0 {
		t.Fatalf("handled=%v code=%d stdout=%q stderr=%q", handled, code, out.String(), errOut.String())
	}
	got := out.String()
	if strings.Contains(got, realStripeKey) || strings.Contains(got, "ambient-key") {
		t.Fatalf("the child saw a real or ambient key: %q", got)
	}
	for _, want := range []string{"key=sk_klph_", "proxy=true ca=true node=1", "status=200 body=balance-ok"} {
		if !strings.Contains(got, want) {
			t.Errorf("child output missing %q: %q", want, got)
		}
	}
	select {
	case a := <-seen:
		if a != "Bearer "+realStripeKey {
			t.Errorf("the provider received %q", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the provider never saw the request")
	}
	if r := auth.reasons(); len(r) != 2 || r[0] != "opened" || r[1] != "run_ended" {
		t.Errorf("session audit reasons = %v, want opened then run_ended", r)
	}
}

func TestTierSelection(t *testing.T) {
	env, _, _ := startPlaceholderDaemon(t)
	c, err := NewClient(lookupOf(env))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.RunSession(RunRequest{Connection: "stripe", Command: []string{"true"}})
	if err != nil || !resp.OK || resp.Session.Tier != TierPlaceholder {
		t.Fatalf("a bound template must default to D3: %+v %v", resp, err)
	}
	if resp.Session.ProxyID == "" || !strings.Contains(resp.Session.CAPEM, "BEGIN CERTIFICATE") || len(resp.Session.CAVars) != 7 {
		t.Errorf("session material incomplete: %+v", resp.Session)
	}
	_ = c.EndSession(resp.Session.ProxyID)

	resp, err = c.RunSession(RunRequest{Connection: "openrouter", Command: []string{"true"}})
	if err != nil || resp.OK || !strings.Contains(resp.Error, "gateway") {
		t.Fatalf("an unbound template must fall to the gateway tier: %+v %v", resp, err)
	}

	resp, _ = c.RunSession(RunRequest{Connection: "openrouter", Tier: TierPlaceholder, Command: []string{"true"}})
	if resp.OK || !strings.Contains(resp.Error, "no host bindings") {
		t.Errorf("D3 for an unbound template: %+v", resp)
	}
	resp, _ = c.RunSession(RunRequest{Connection: "stripe", Runtime: "gateway_sdk", Command: []string{"true"}})
	if resp.Session != nil && resp.Session.Tier == TierPlaceholder {
		t.Errorf("an explicit gateway runtime must not select D3")
	}
}

func TestPlaceholderTierUnavailableWithoutAManager(t *testing.T) {
	_, env := startDaemon(t, "")
	c, err := NewClient(lookupOf(env))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := c.RunSession(RunRequest{Connection: "stripe", Tier: TierPlaceholder, Command: []string{"true"}})
	if resp.OK || resp.Code != CodeUnavailable || !strings.Contains(resp.Error, "D3") {
		t.Fatalf("got %+v", resp)
	}
}

func TestProxyOpRejectsUnknownSession(t *testing.T) {
	env, _, _ := startPlaceholderDaemon(t)
	c, err := NewClient(lookupOf(env))
	if err != nil {
		t.Fatal(err)
	}
	addr, stop, err := c.ForwardProxy("no-such-session")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _ := conn.Read(make([]byte, 16)); n != 0 {
		t.Fatalf("an unknown session answered %d bytes", n)
	}
}

func TestCABundleHoldsRootsAndSessionCA(t *testing.T) {
	root := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	file := t.TempDir() + "/roots.pem"
	if err := os.WriteFile(file, []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	session := "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
	path, cleanup, warn, err := writeCABundle(lookupOf(map[string]string{"SSL_CERT_FILE": file}), session)
	if err != nil || warn != nil {
		t.Fatalf("err=%v warn=%v", err, warn)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "AAAA") || !strings.Contains(string(data), "BBBB") {
		t.Errorf("bundle %q", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("bundle mode %v", info.Mode())
	}
	cleanup()
	if _, err := os.Stat(path); err == nil {
		t.Error("bundle survived cleanup")
	}
}
