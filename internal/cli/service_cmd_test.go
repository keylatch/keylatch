package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/testutil"
)

var serviceCanary = "canary" + "-cli-service-" + "98fe"

type serviceFixture struct {
	broker *syncBroker
	out    *bytes.Buffer
	sealed []sealedCall
}

type sealedCall struct {
	scope, connection, dest string
	capability              []byte
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	testutil.SetupHermeticConfig(t)
	testutil.ClearLLMSessionEnv(t)
	f := &serviceFixture{broker: &syncBroker{}, out: &bytes.Buffer{}}
	prevInst, prevDial, prevSeal := brokerInstalled, dialBroker, sealCredential
	brokerInstalled = func(llmcontext.Lookup) bool { return true }
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) { return f.broker, nil }
	sealCredential = func(_ context.Context, scope, connection, dest string, capability []byte) error {
		f.sealed = append(f.sealed, sealedCall{scope, connection, dest, append([]byte(nil), capability...)})
		return nil
	}
	t.Cleanup(func() { brokerInstalled, dialBroker, sealCredential = prevInst, prevDial, prevSeal })
	return f
}

func (f *serviceFixture) run(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewRootCommand()
	cmd.SetOut(f.out)
	cmd.SetErr(f.out)
	cmd.SetArgs(append([]string{"service"}, args...))
	return cmd.ExecuteContext(context.Background())
}

func TestRenderUnitLinesJSON(t *testing.T) {
	f := newServiceFixture(t)
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{OK: true, Service: &brokerapi.ServiceResult{Services: []brokerapi.ServiceInfo{{Connection: "app-db", Unit: "app.service", Scope: "system"}}}}
	}
	if err := f.run(t, "render-unit-lines", "app-db", "--format", "json"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(f.out.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %s", f.out)
	}
	want := []string{
		"LoadCredentialEncrypted=keylatch-app-db:/etc/credstore.encrypted/keylatch-app-db.cred",
		"Environment=KEYLATCH_SERVICE_CONNECTION=app-db",
	}
	if strings.Join(doc.Lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines = %v", doc.Lines)
	}

	f.out.Reset()
	if err := f.run(t, "render-unit-lines", "app-db", "--format", "ini", "--scope", "user"); err != nil {
		t.Fatal(err)
	}
	if got := f.out.String(); !strings.HasPrefix(got, "[Service]\nLoadCredentialEncrypted=keylatch-app-db:") || !strings.Contains(got, "/.config/credstore.encrypted/keylatch-app-db.cred\n") {
		t.Fatalf("ini = %q", got)
	}
	// The enrollment decides the scope when --scope is not given.
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{OK: true, Service: &brokerapi.ServiceResult{Services: []brokerapi.ServiceInfo{{Connection: "app-db", Unit: "app.service", Scope: "user"}}}}
	}
	f.out.Reset()
	if err := f.run(t, "render-unit-lines", "app-db", "--format", "json"); err != nil || !strings.Contains(f.out.String(), ".config/credstore.encrypted") {
		t.Fatalf("enrolled scope: %v %s", err, f.out)
	}
	for _, bad := range [][]string{{"render-unit-lines", "app-db", "--format", "yaml"}, {"render-unit-lines", "../x"}} {
		if err := f.run(t, bad...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestServiceEnrollNeedsPresence(t *testing.T) {
	f := newServiceFixture(t)
	f.broker.refuse = true
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		t.Fatal("enroll reached the daemon without a proof")
		return brokerapi.Response{}
	}
	assertSecurityBlock(t, f.run(t, "enroll", "app-db", "--unit", "app.service"))
	if len(f.sealed) != 0 {
		t.Fatal("a refused enrollment sealed a credential")
	}
	t.Setenv("CLAUDECODE", "1")
	assertSecurityBlock(t, f.run(t, "enroll", "app-db", "--unit", "app.service"))
	assertSecurityBlock(t, f.run(t, "revoke", "app-db"))
}

func TestSealedBlobIsCapabilityNotSecret(t *testing.T) {
	f := newServiceFixture(t)
	capability := bytes.Repeat([]byte{0x5a}, 32)
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response {
		if req.Op != brokerapi.OpServiceEnroll || len(req.Service.Units) != 2 || req.Service.Scope != "system" || !req.Service.AllowTransient {
			t.Errorf("request = %+v", req.Service)
		}
		// The command wipes what it is given, so hand it a copy.
		return brokerapi.Response{OK: true, Service: &brokerapi.ServiceResult{Capability: bytes.Clone(capability)}}
	}
	if err := f.run(t, "enroll", "app-db", "--unit", "a.service", "--unit", "b.service", "--allow-transient"); err != nil {
		t.Fatalf("enroll: %v\n%s", err, f.out)
	}
	if len(f.sealed) != 1 {
		t.Fatalf("sealed %d times", len(f.sealed))
	}
	s := f.sealed[0]
	if s.scope != "system" || s.connection != "app-db" || s.dest != "/etc/credstore.encrypted/keylatch-app-db.cred" {
		t.Fatalf("sealed = %+v", s)
	}
	if !bytes.Equal(s.capability, capability) || bytes.Contains(s.capability, []byte(serviceCanary)) {
		t.Fatal("the sealed blob must be exactly the capability")
	}
	for _, r := range f.broker.requests {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), serviceCanary) {
			t.Fatalf("a request carries a secret: %s", b)
		}
	}
	out := f.out.String()
	if !strings.Contains(out, "LoadCredentialEncrypted=keylatch-app-db:/etc/credstore.encrypted/keylatch-app-db.cred") {
		t.Fatalf("enroll should print the unit lines:\n%s", out)
	}
	for _, args := range [][]string{
		{"enroll", "app-db"},
		{"enroll", "../x", "--unit", "a.service"},
		{"enroll", "app-db", "--unit", "a.service", "--scope", "global"},
	} {
		if err := f.run(t, args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestServiceListAndRevoke(t *testing.T) {
	f := newServiceFixture(t)
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response {
		switch req.Op {
		case brokerapi.OpServiceList:
			return brokerapi.Response{OK: true, Service: &brokerapi.ServiceResult{Services: []brokerapi.ServiceInfo{
				{Connection: "app-db", Unit: "a.service", Scope: "system"},
				{Connection: "mail", Unit: "m.service", Scope: "user", Changed: true, Detail: "the unit file or a drop-in changed"},
			}}}
		case brokerapi.OpServiceRevoke:
			if req.Service.Connection != "app-db" || req.Service.Unit != "a.service" {
				t.Errorf("revoke = %+v", req.Service)
			}
			return brokerapi.Response{OK: true}
		}
		return brokerapi.Response{}
	}
	if err := f.run(t, "list"); err != nil || !strings.Contains(f.out.String(), "CHANGED: the unit file") || !strings.Contains(f.out.String(), "a.service") {
		t.Fatalf("list = %v\n%s", err, f.out)
	}
	f.out.Reset()
	if err := f.run(t, "list", "--json"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services []brokerapi.ServiceInfo `json:"services"`
	}
	if json.Unmarshal(f.out.Bytes(), &doc) != nil || len(doc.Services) != 2 || !doc.Services[1].Changed {
		t.Fatalf("json = %s", f.out)
	}
	f.out.Reset()
	if err := f.run(t, "revoke", "app-db", "--unit", "a.service"); err != nil || !strings.Contains(f.out.String(), "revoked a.service") {
		t.Fatalf("revoke = %v\n%s", err, f.out)
	}
	f.out.Reset()
	f.broker.answer = func(brokerapi.Request) brokerapi.Response { return brokerapi.Response{OK: true} }
	if err := f.run(t, "revoke", "app-db"); err != nil || !strings.Contains(f.out.String(), "revoked every unit") {
		t.Fatalf("revoke all = %v\n%s", err, f.out)
	}
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{Code: brokerapi.CodeUnavailable, Error: "down"}
	}
	if err := f.run(t, "list"); err == nil {
		t.Fatal("a failing daemon must fail the list")
	}
}

func TestCredentialPaths(t *testing.T) {
	if p, err := credentialPath("system", "x"); err != nil || p != "/etc/credstore.encrypted/keylatch-x.cred" {
		t.Fatalf("system = %q %v", p, err)
	}
	if p, err := credentialPath("user", "x"); err != nil || !strings.HasSuffix(p, ".config/credstore.encrypted/keylatch-x.cred") {
		t.Fatalf("user = %q %v", p, err)
	}
}
