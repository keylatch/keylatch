package cli

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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/machinecert"
	"github.com/keylatch/keylatch/internal/testutil"
)

type machineFixture struct {
	broker *syncBroker
	out    *bytes.Buffer
	ca     *x509.Certificate
	caKey  ed25519.PrivateKey
}

func newMachineFixture(t *testing.T) *machineFixture {
	t.Helper()
	testutil.SetupHermeticConfig(t)
	testutil.ClearLLMSessionEnv(t)
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := machinecert.CA(caKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &machineFixture{broker: &syncBroker{}, out: &bytes.Buffer{}, ca: ca, caKey: caKey}
	prevInst, prevDial := brokerInstalled, dialBroker
	brokerInstalled = func(llmcontext.Lookup) bool { return true }
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) { return f.broker, nil }
	t.Cleanup(func() { brokerInstalled, dialBroker = prevInst, prevDial })
	return f
}

func (f *machineFixture) run(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewRootCommand()
	cmd.SetOut(f.out)
	cmd.SetErr(f.out)
	cmd.SetArgs(args)
	return cmd.ExecuteContext(context.Background())
}

// issuing answers a machine.issue the way the broker does: it signs the key
// the client sent.
func (f *machineFixture) issuing(t *testing.T) {
	t.Helper()
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response { return f.issueAnswer(t, req) }
}

func (f *machineFixture) issueAnswer(t *testing.T, req brokerapi.Request) brokerapi.Response {
	t.Helper()
	if req.Op != brokerapi.OpMachineIssue {
		return brokerapi.Response{OK: true}
	}
	m := req.Machine
	der, _, err := machinecert.IssueClient(f.ca, f.caKey, ed25519.PublicKey(m.PublicKey), machinecert.Claims{Name: m.Name, Domain: m.Domain, Caps: m.Caps, NotAfter: time.Now().Add(time.Duration(m.TTLSeconds) * time.Second)}, time.Now())
	if err != nil {
		t.Error(err)
	}
	return brokerapi.Response{OK: true, Machine: &brokerapi.MachineResult{Certificate: machinecert.PEM(der), CA: machinecert.PEM(f.ca.Raw)}}
}

func TestMachineIssueWritesBundleAndNeverSendsThePrivateKey(t *testing.T) {
	f := newMachineFixture(t)
	f.issuing(t)
	out := filepath.Join(t.TempDir(), "guest.pem")
	if err := f.run(t, "machine", "issue", "--domain", "apps", "--name", "ci-1", "--caps", "call", "--ttl", "2h", "--out", out); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(out)
	if err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("bundle: %v %v", st, err)
	}
	data, _ := os.ReadFile(out)
	key, cert, _, _, err := machinecert.ParseBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := machinecert.ClaimsOf(cert)
	if err != nil || claims.Domain != "apps" || claims.Name != "ci-1" {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	for _, r := range f.broker.requests {
		raw, _ := json.Marshal(r)
		if bytes.Contains(raw, key.Seed()) {
			t.Fatal("the private key was sent to the broker")
		}
		if r.Op == brokerapi.OpMachineIssue && r.Machine.TTLSeconds != 7200 {
			t.Fatalf("ttl = %d", r.Machine.TTLSeconds)
		}
	}
	if err := f.run(t, "machine", "issue", "--domain", "apps", "--name", "ci-1", "--out", out); err == nil {
		t.Fatal("an existing file was overwritten")
	}
}

func TestMachineIssueNeedsPresence(t *testing.T) {
	f := newMachineFixture(t)
	f.issuing(t)
	f.broker.refuse = true
	out := filepath.Join(t.TempDir(), "guest.pem")
	if err := f.run(t, "machine", "issue", "--domain", "apps", "--name", "ci-1", "--out", out); err == nil {
		t.Fatal("issue succeeded without presence")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused issue left a credential file")
	}
}

func TestMachineHumanOnly(t *testing.T) {
	f := newMachineFixture(t)
	t.Setenv("CLAUDECODE", "1")
	for _, args := range [][]string{
		{"machine", "issue", "--domain", "apps", "--name", "ci-1", "--out", filepath.Join(t.TempDir(), "x")},
		{"machine", "revoke", "ci-1"},
		{"config", "set", "gateway.machine_listen", "127.0.0.1:7443"},
	} {
		if err := f.run(t, args...); err == nil {
			t.Fatalf("%v ran for an agent session", args)
		}
	}
	if len(f.broker.requests) != 0 {
		t.Fatalf("the broker saw %d requests", len(f.broker.requests))
	}
}

func TestMachineRevokeAndList(t *testing.T) {
	f := newMachineFixture(t)
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response {
		if req.Op == brokerapi.OpMachineList {
			return brokerapi.Response{OK: true, Machine: &brokerapi.MachineResult{Machines: []brokerapi.MachineInfo{
				{Name: "ci-1", Domain: "apps", Caps: []string{"call"}, NotAfter: "2027-01-01T00:00:00Z"},
				{Name: "ci-2", Domain: "ops", Caps: []string{"call"}, Revoked: true},
			}}}
		}
		return brokerapi.Response{OK: true}
	}
	if err := f.run(t, "machine", "revoke", "ci-1"); err != nil || !strings.Contains(f.out.String(), "revoked ci-1") {
		t.Fatalf("revoke: %v %s", err, f.out)
	}
	f.out.Reset()
	if err := f.run(t, "machine", "list", "--json"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Machines []brokerapi.MachineInfo `json:"machines"`
	}
	if err := json.Unmarshal(f.out.Bytes(), &doc); err != nil || len(doc.Machines) != 2 {
		t.Fatalf("list = %s", f.out)
	}
	f.out.Reset()
	if err := f.run(t, "machine", "list"); err != nil || !strings.Contains(f.out.String(), "active until 2027") || !strings.Contains(f.out.String(), "revoked") {
		t.Fatalf("list text: %v %s", err, f.out)
	}
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{Code: brokerapi.CodeUnavailable, Error: "down"}
	}
	if err := f.run(t, "machine", "list"); err == nil {
		t.Fatal("list hid a broker failure")
	}
}

func TestWildcardBindRefused(t *testing.T) {
	f := newMachineFixture(t)
	f.broker.answer = func(brokerapi.Request) brokerapi.Response { return brokerapi.Response{OK: true} }
	for _, addr := range []string{"0.0.0.0:7443", "[::]:7443", ":7443"} {
		if err := f.run(t, "config", "set", "gateway.machine_listen", addr); err == nil {
			t.Fatalf("%s was accepted", addr)
		}
	}
	if len(f.broker.requests) != 0 {
		t.Fatal("a refused address reached the broker")
	}
	if err := f.run(t, "config", "set", "gateway.machine_listen", "127.0.0.1:7443"); err != nil {
		t.Fatal(err)
	}
	if err := f.run(t, "config", "set", "gateway.machine_listen", "0.0.0.0:7443", "--allow-wildcard"); err != nil {
		t.Fatal(err)
	}
	var listens []brokerapi.MachineRequest
	for _, r := range f.broker.requests {
		if r.Op == brokerapi.OpMachineListen {
			listens = append(listens, *r.Machine)
		}
	}
	if len(listens) != 2 || listens[0].AllowWildcard || !listens[1].AllowWildcard {
		t.Fatalf("listen requests = %+v", listens)
	}
}

type fakeMachineBackend struct {
	calls   []gateway.MachineCall
	refused []string
	reply   gateway.MachineCallResult
	err     error
}

func (b *fakeMachineBackend) Authenticate(cert *x509.Certificate) (gateway.MachinePrincipal, error) {
	c, err := machinecert.ClaimsOf(cert)
	if err != nil {
		return gateway.MachinePrincipal{}, err
	}
	return gateway.MachinePrincipal{Name: c.Name, Domain: c.Domain, Caps: c.Caps}, nil
}

func (b *fakeMachineBackend) Call(_ context.Context, _ gateway.MachinePrincipal, c gateway.MachineCall) (gateway.MachineCallResult, error) {
	b.calls = append(b.calls, c)
	return b.reply, b.err
}

func (b *fakeMachineBackend) Refused(_ context.Context, _ *gateway.MachinePrincipal, reason string) {
	b.refused = append(b.refused, reason)
}

// startListener serves the machine listener on a loopback address and returns
// the address and a credential file for a machine of the given domain.
func (f *machineFixture) startListener(t *testing.T, backend gateway.MachineBackend, domain string) (addr, keyFile string) {
	t.Helper()
	spub, skey, _ := ed25519.GenerateKey(rand.Reader)
	sder, err := machinecert.IssueServer(f.ca, f.caKey, spub, []string{"127.0.0.1"}, time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.ca)
	l, err := gateway.NewMachineListener(gateway.MachineListenerConfig{
		Addr: "127.0.0.1:7443", ClientCAs: pool, Backend: backend,
		ServerCert: tls.Certificate{Certificate: [][]byte{sder}, PrivateKey: skey},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(l.Handler())
	srv.TLS = l.TLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)

	f.issuing(t)
	keyFile = filepath.Join(t.TempDir(), "guest.pem")
	if err := f.run(t, "machine", "issue", "--domain", domain, "--name", "ci-1", "--out", keyFile); err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	return srv.Listener.Addr().String(), keyFile
}

func TestRemoteCall(t *testing.T) {
	f := newMachineFixture(t)
	backend := &fakeMachineBackend{reply: gateway.MachineCallResult{Status: 200, DurationMs: 3, Body: []byte(`{"data":[]}`)}}
	addr, key := f.startListener(t, backend, "apps")

	if err := f.run(t, "call", "--remote", addr, "--machine-key", key, "mach-demo", "list-models", "--param", "a=b"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), `{"data":[]}`) {
		t.Fatalf("output = %q", f.out)
	}
	if len(backend.calls) != 1 || backend.calls[0].Connection != "mach-demo" || backend.calls[0].Params["a"] != "b" || backend.calls[0].Namespace != "" {
		t.Fatalf("calls = %+v", backend.calls)
	}
	f.out.Reset()
	if err := f.run(t, "call", "--remote", addr, "--machine-key", key, "mach-demo", "list-models", "--json"); err != nil || !strings.Contains(f.out.String(), `"status_code":200`) {
		t.Fatalf("json: %v %s", err, f.out)
	}
}

func TestCrossDomainRefused(t *testing.T) {
	f := newMachineFixture(t)
	backend := &fakeMachineBackend{}
	addr, key := f.startListener(t, backend, "apps")
	err := f.run(t, "call", "--remote", addr, "--machine-key", key, "--namespace", "other", "mach-demo", "list-models")
	if err == nil || !strings.Contains(err.Error(), "cross_domain") {
		t.Fatalf("cross-domain call = %v", err)
	}
	if len(backend.calls) != 0 || len(backend.refused) != 1 {
		t.Fatalf("calls %v refused %v", backend.calls, backend.refused)
	}
}

func TestRemoteCallFailures(t *testing.T) {
	f := newMachineFixture(t)
	backend := &fakeMachineBackend{err: gateway.ErrMachineNotFound}
	addr, key := f.startListener(t, backend, "apps")
	if err := f.run(t, "call", "--remote", addr, "--machine-key", key, "mach-demo", "list-models"); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("not found = %v", err)
	}
	backend.err = errors.New("boom")
	if err := f.run(t, "call", "--remote", addr, "--machine-key", key, "mach-demo", "list-models"); err == nil {
		t.Fatal("a failed call succeeded")
	}
	backend.err, backend.reply = nil, gateway.MachineCallResult{Status: 404, Body: []byte("{}")}
	if err := f.run(t, "call", "--remote", addr, "--machine-key", key, "mach-demo", "list-models"); err == nil {
		t.Fatal("a provider 404 exited 0")
	}
	for _, args := range [][]string{
		{"call", "--remote", addr, "mach-demo", "list-models"},
		{"call", "--remote", addr, "--machine-key", filepath.Join(t.TempDir(), "missing"), "mach-demo", "list-models"},
		{"call", "--remote", "no-port", "--machine-key", key, "mach-demo", "list-models"},
		{"call", "--remote", addr, "--machine-key", key, "mach-demo", "list-models", "--param", "bad"},
	} {
		if err := f.run(t, args...); err == nil {
			t.Fatalf("%v succeeded", args)
		}
	}
	// A listener the key's CA did not sign is not trusted.
	other := newMachineFixture(t)
	oaddr, _ := other.startListener(t, backend, "apps")
	if err := f.run(t, "call", "--remote", oaddr, "--machine-key", key, "mach-demo", "list-models"); err == nil {
		t.Fatal("a server from another CA was trusted")
	}
	// Plain TCP is not a machine listener.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	if err := f.run(t, "call", "--remote", ln.Addr().String(), "--machine-key", key, "mach-demo", "list-models"); err == nil {
		t.Fatal("a closed connection succeeded")
	}
}

func TestRemoteCallUnreadableReply(t *testing.T) {
	f := newMachineFixture(t)
	_, key := f.startListener(t, &fakeMachineBackend{}, "apps")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) }))
	defer srv.Close()
	prev := remoteHTTP
	remoteHTTP = func(*tls.Config) *http.Client { return srv.Client() }
	defer func() { remoteHTTP = prev }()
	if err := f.run(t, "call", "--remote", srv.Listener.Addr().String(), "--machine-key", key, "mach-demo", "list-models"); err == nil {
		t.Fatal("an unreadable reply succeeded")
	}
}

func TestMachineIssueRefusesASymlinkAndNeverFollowsIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	f := newMachineFixture(t)
	f.issuing(t)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "guest.pem")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := f.run(t, "machine", "issue", "--domain", "apps", "--name", "ci-1", "--out", link); err == nil {
		t.Fatal("issue wrote through a symlink")
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep" {
		t.Fatalf("the symlink's target was changed: %q", got)
	}
	dangling := filepath.Join(dir, "dangling.pem")
	if err := os.Symlink(filepath.Join(dir, "created-by-attacker"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := f.run(t, "machine", "issue", "--domain", "apps", "--name", "ci-2", "--out", dangling); err == nil {
		t.Fatal("issue followed a dangling symlink")
	}
	if _, err := os.Stat(filepath.Join(dir, "created-by-attacker")); err == nil {
		t.Fatal("a file was created through a dangling symlink")
	}
	for _, r := range f.broker.requests {
		if r.Op == brokerapi.OpMachineIssue {
			t.Fatal("a credential was issued although the file could not be created")
		}
	}
}

func TestMachineIssueRevokesWhenTheFileCannotBeWritten(t *testing.T) {
	f := newMachineFixture(t)
	f.issuing(t)
	prev := writeBundle
	writeBundle = func(*os.File, []byte) error { return errors.New("no space left on device") }
	defer func() { writeBundle = prev }()
	out := filepath.Join(t.TempDir(), "guest.pem")
	err := f.run(t, "machine", "issue", "--domain", "apps", "--name", "ci-1", "--out", out)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("issue = %v", err)
	}
	var ops []brokerapi.Op
	for _, r := range f.broker.requests {
		if r.Op == brokerapi.OpMachineIssue || r.Op == brokerapi.OpMachineRevoke {
			ops = append(ops, r.Op)
		}
	}
	if len(ops) != 2 || ops[1] != brokerapi.OpMachineRevoke {
		t.Fatalf("broker operations = %v", ops)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a partial credential file was left")
	}

	// When the revoke cannot be made either, the message says how to do it.
	f.broker.requests = nil
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response {
		if req.Op == brokerapi.OpMachineRevoke {
			return brokerapi.Response{Code: brokerapi.CodeUnavailable, Error: "down"}
		}
		return f.issueAnswer(t, req)
	}
	err = f.run(t, "machine", "issue", "--domain", "apps", "--name", "ci-2", "--out", out)
	if err == nil || !strings.Contains(err.Error(), "keylatch machine revoke ci-2") {
		t.Fatalf("revoke failure = %v", err)
	}
}
