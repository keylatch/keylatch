//go:build unix

package brokerd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/template"
)

var machineCanary = "canary" + "-machine-" + "5d2e"

type machineRig struct {
	h     *harness
	uid   uint32
	calls []string
	creds []string
}

func newMachineRig(t *testing.T) *machineRig {
	t.Helper()
	r := &machineRig{uid: 1000}
	r.h = newHarness(t, func(c *Config) {
		c.CallAction = func(_ context.Context, _, provider, action string, _ map[string]string, cred string) (*runner.ActionResult, error) {
			r.calls = append(r.calls, provider+"/"+action)
			r.creds = append(r.creds, cred)
			return &runner.ActionResult{StatusCode: 200, Body: []byte(`{"echo":"` + cred + `"}`)}, nil
		}
	})
	return r
}

func (r *machineRig) issue(t *testing.T, name, domain string, caps []string, ttl int64) (brokerapi.Response, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpMachineIssue, Machine: &brokerapi.MachineRequest{
		Name: name, Domain: domain, Caps: caps, TTLSeconds: ttl, PublicKey: pub,
	}})
	return r.h.send(t, r.uid, req), key
}

func (r *machineRig) principal(t *testing.T, resp brokerapi.Response) (gateway.MachinePrincipal, error) {
	t.Helper()
	block := resp.Machine.Certificate
	cert, err := x509.ParseCertificate(derOf(t, block))
	if err != nil {
		t.Fatal(err)
	}
	return machineBackend{r.h.srv}.Authenticate(cert)
}

func derOf(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		t.Fatal("no certificate")
	}
	return blk.Bytes
}

func TestMachineIssueNeedsPresence(t *testing.T) {
	r := newMachineRig(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	resp := r.h.send(t, r.uid, brokerapi.Request{Op: brokerapi.OpMachineIssue, Machine: &brokerapi.MachineRequest{
		Name: "ci-1", Domain: "apps", Caps: []string{"call"}, TTLSeconds: 3600, PublicKey: pub,
	}})
	if resp.OK || resp.Code != brokerapi.CodePresenceRequired {
		t.Fatalf("issue without a proof = %+v", resp)
	}
	if n := r.h.rec.count(audit.ActionMachineIssue); n != 0 {
		t.Fatalf("%d issue events for a refused request", n)
	}
}

func TestMachineIssueListRevoke(t *testing.T) {
	r := newMachineRig(t)
	resp, _ := r.issue(t, "ci-1", "apps", []string{"call"}, 3600)
	if !resp.OK || resp.Machine == nil || len(resp.Machine.Certificate) == 0 || len(resp.Machine.CA) == 0 {
		t.Fatalf("issue = %+v", resp)
	}
	if again, _ := r.issue(t, "ci-1", "apps", []string{"call"}, 3600); again.OK {
		t.Fatal("a second active credential with the same name was issued")
	}
	list := r.h.send(t, r.uid, brokerapi.Request{Op: brokerapi.OpMachineList, Machine: &brokerapi.MachineRequest{}})
	if !list.OK || len(list.Machine.Machines) != 1 || list.Machine.Machines[0].Domain != "apps" || list.Machine.Machines[0].Revoked {
		t.Fatalf("list = %+v", list)
	}
	if other := r.h.send(t, 2000, brokerapi.Request{Op: brokerapi.OpMachineList, Machine: &brokerapi.MachineRequest{}}); len(other.Machine.Machines) != 0 {
		t.Fatalf("another user sees %+v", other.Machine.Machines)
	}

	p, err := r.principal(t, resp)
	if err != nil || p.Name != "ci-1" || p.Domain != "apps" {
		t.Fatalf("principal = %+v, %v", p, err)
	}

	rev := r.h.send(t, r.uid, r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpMachineRevoke, Machine: &brokerapi.MachineRequest{Name: "ci-1"}}))
	if !rev.OK {
		t.Fatalf("revoke = %+v", rev)
	}
	if _, err := r.principal(t, resp); !errors.Is(err, gateway.ErrMachineRevoked) {
		t.Fatalf("a revoked credential authenticates: %v", err)
	}
	if rev := r.h.send(t, r.uid, r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpMachineRevoke, Machine: &brokerapi.MachineRequest{Name: "ci-1"}})); rev.OK || rev.Code != brokerapi.CodeNotFound {
		t.Fatalf("revoking twice = %+v", rev)
	}
	if r.h.rec.count(audit.ActionMachineIssue) != 1 || r.h.rec.count(audit.ActionMachineRevoke) != 1 {
		t.Fatal("issue and revoke are not each audited once")
	}
	// A revoked name can be issued again.
	if again, _ := r.issue(t, "ci-1", "apps", []string{"call"}, 3600); !again.OK {
		t.Fatalf("reissue = %+v", again)
	}
}

func TestMachineExpired(t *testing.T) {
	r := newMachineRig(t)
	resp, _ := r.issue(t, "ci-1", "apps", []string{"call"}, 120)
	*r.h.now = r.h.now.Add(3 * time.Minute)
	if _, err := r.principal(t, resp); !errors.Is(err, gateway.ErrMachineRevoked) {
		t.Fatalf("an expired credential authenticates: %v", err)
	}
}

func TestMachineUnknownSerialRefused(t *testing.T) {
	r := newMachineRig(t)
	resp, _ := r.issue(t, "ci-1", "apps", []string{"call"}, 3600)
	// A broker with a fresh registry has never issued this certificate.
	other := newMachineRig(t)
	if _, err := other.principal(t, resp); err == nil {
		t.Fatal("a certificate the broker did not issue authenticates")
	}
	var nocert x509.Certificate
	if _, err := (machineBackend{r.h.srv}).Authenticate(&nocert); err == nil {
		t.Fatal("a certificate without claims authenticates")
	}
}

const machineProvider = "mach-demo"

func registerMachineDemo(t *testing.T) registry.ConnectionTemplate {
	t.Helper()
	tmpl := registry.ConnectionTemplate{
		Provider: machineProvider, DisplayName: "Machine demo", Category: "ai",
		SecretFields: []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
		TestStrategy: registry.TestStrategy{Kind: "http_get", Endpoint: "https://api.example.com/v1/models"},
		Actions:      map[string]template.Action{"list-models": {Method: "GET", Path: "/v1/models"}},
	}
	if err := registry.Register(tmpl); err != nil && !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
	got, err := registry.Get(machineProvider)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func seedMachineSecret(t *testing.T, r *machineRig, domain string) {
	t.Helper()
	tmpl := registerMachineDemo(t)
	p, err := r.h.srv.partition(context.Background(), r.uid)
	if err != nil {
		t.Fatal(err)
	}
	path := connections.SecretFieldPath(domain, tmpl.Category, machineProvider, tmpl.SecretFields[0].Name)
	if _, err := p.store.Put(context.Background(), path, []byte(machineCanary)); err != nil {
		t.Fatal(err)
	}
}

func TestMachineCallUsesCertificateDomain(t *testing.T) {
	r := newMachineRig(t)
	seedMachineSecret(t, r, "apps")
	resp, _ := r.issue(t, "ci-1", "apps", []string{"call"}, 3600)
	p, err := r.principal(t, resp)
	if err != nil {
		t.Fatal(err)
	}
	b := machineBackend{r.h.srv}
	res, err := b.Call(context.Background(), p, gateway.MachineCall{Connection: machineProvider, Action: "list-models"})
	if err != nil || res.Status != 200 {
		t.Fatalf("call = %+v, %v", res, err)
	}
	if strings.Contains(string(res.Body), machineCanary) {
		t.Fatalf("the response carries the credential: %s", res.Body)
	}
	if len(r.creds) != 1 || r.creds[0] != machineCanary {
		t.Fatalf("the provider did not get the stored credential: %v", r.creds)
	}
	ev, ok := r.h.rec.last(audit.ActionCall)
	if !ok || ev.Extra["caller_kind"] != "machine" || strings.Contains(strings.Join(mapStrings(ev.Extra), " "), machineCanary) {
		t.Fatalf("call event = %+v", ev)
	}

	// A credential for another domain finds nothing under its own.
	other, _ := r.issue(t, "ci-2", "other", []string{"call"}, 3600)
	op, _ := r.principal(t, other)
	if _, err := b.Call(context.Background(), op, gateway.MachineCall{Connection: machineProvider, Action: "list-models"}); !errors.Is(err, gateway.ErrMachineNotFound) {
		t.Fatalf("cross-domain call = %v", err)
	}
	if _, err := b.Call(context.Background(), p, gateway.MachineCall{Connection: "nope", Action: "x"}); !errors.Is(err, gateway.ErrMachineNotFound) {
		t.Fatalf("unknown connection = %v", err)
	}
	if _, err := b.Call(context.Background(), p, gateway.MachineCall{Connection: machineProvider, Action: "nope"}); !errors.Is(err, gateway.ErrMachineNotFound) {
		t.Fatalf("unknown action = %v", err)
	}
	r.h.send(t, r.uid, r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpMachineRevoke, Machine: &brokerapi.MachineRequest{Name: "ci-1"}}))
	if _, err := b.Call(context.Background(), p, gateway.MachineCall{Connection: machineProvider, Action: "list-models"}); !errors.Is(err, gateway.ErrMachineRevoked) {
		t.Fatalf("call after revoke = %v", err)
	}
}

func mapStrings(m map[string]any) []string {
	var out []string
	for k, v := range m {
		out = append(out, k, strings.TrimSpace(anyString(v)))
	}
	return out
}

func anyString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestMachineCallDispatchFailureAudited(t *testing.T) {
	r := newMachineRig(t)
	seedMachineSecret(t, r, "apps")
	r.h.srv.cfg.CallAction = func(context.Context, string, string, string, map[string]string, string) (*runner.ActionResult, error) {
		return nil, errors.New("upstream down")
	}
	resp, _ := r.issue(t, "ci-1", "apps", []string{"call"}, 3600)
	p, _ := r.principal(t, resp)
	if _, err := (machineBackend{r.h.srv}).Call(context.Background(), p, gateway.MachineCall{Connection: machineProvider, Action: "list-models"}); err == nil {
		t.Fatal("a failed dispatch succeeded")
	}
	if ev, _ := r.h.rec.last(audit.ActionCall); ev.Outcome != audit.OutcomeError {
		t.Fatalf("outcome = %v", ev.Outcome)
	}
}

func TestMachineRefusedAudited(t *testing.T) {
	r := newMachineRig(t)
	b := machineBackend{r.h.srv}
	b.Refused(context.Background(), nil, "bad cert")
	b.Refused(context.Background(), &gateway.MachinePrincipal{Name: "ci-1"}, "cross-domain call")
	if n := r.h.rec.count(audit.ActionSecurityBlock); n != 2 {
		t.Fatalf("security.block events = %d", n)
	}
}

func TestMachineListenRefusesWildcardAndRestarts(t *testing.T) {
	r := newMachineRig(t)
	listens := make(chan string, 4)
	r.h.srv.cfg.MachineListen = func(_, addr string) (net.Listener, error) {
		listens <- addr
		return net.Listen("tcp", "127.0.0.1:0")
	}
	set := func(addr string, wild bool) brokerapi.Response {
		return r.h.send(t, r.uid, r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpMachineListen, Machine: &brokerapi.MachineRequest{Listen: addr, AllowWildcard: wild}}))
	}
	if resp := set("0.0.0.0:7443", false); resp.OK {
		t.Fatalf("a wildcard bind was accepted: %+v", resp)
	}
	if _, err := os.Stat(r.h.srv.listenFile()); err == nil {
		t.Fatal("a refused address was stored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.h.srv.StartMachineListener(ctx)
	if resp := set("127.0.0.1:7443", false); !resp.OK {
		t.Fatalf("listen = %+v", resp)
	}
	select {
	case got := <-listens:
		if got != "127.0.0.1:7443" {
			t.Fatalf("bound %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener did not bind")
	}
	if resp := set("0.0.0.0:7443", true); !resp.OK {
		t.Fatalf("explicit wildcard = %+v", resp)
	}
	if !wildcardAllowedBefore("0.0.0.0:7443") || wildcardAllowedBefore("127.0.0.1:7443") {
		t.Fatal("wildcardAllowedBefore")
	}
	if r.h.rec.count(audit.ActionPolicyChange) != 2 {
		t.Fatal("listen changes are not audited")
	}
}

func TestBaseURLOf(t *testing.T) {
	if got, err := baseURLOf(registry.ConnectionTemplate{TestStrategy: registry.TestStrategy{Endpoint: "https://api.example.com/v1/models"}}); err != nil || got != "https://api.example.com" {
		t.Fatalf("baseURLOf = %q, %v", got, err)
	}
	for _, ep := range []string{"", "no-scheme", "https:///x"} {
		if _, err := baseURLOf(registry.ConnectionTemplate{TestStrategy: registry.TestStrategy{Endpoint: ep}}); err == nil {
			t.Fatalf("baseURLOf(%q) succeeded", ep)
		}
	}
}
