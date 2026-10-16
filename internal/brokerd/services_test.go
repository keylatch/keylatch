//go:build unix

package brokerd

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/registry"
)

var svcCanary = "canary" + "-service-" + "c4d1"

type fakeUnits struct {
	mu    sync.Mutex
	info  map[string]UnitInfo
	err   error
	calls []string
}

func (f *fakeUnits) Inspect(_ context.Context, scope string, owner uint32, unit string) (UnitInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, scope+":"+unit)
	if f.err != nil {
		return UnitInfo{}, f.err
	}
	i, ok := f.info[unit]
	if !ok {
		return UnitInfo{}, errors.New("no such unit")
	}
	return i, nil
}

type svcRig struct {
	h     *harness
	units *fakeUnits
	uid   uint32
}

func newSvcRig(t *testing.T) *svcRig {
	t.Helper()
	units := &fakeUnits{info: map[string]UnitInfo{
		"app.service": {FragmentPath: "/etc/systemd/system/app.service", ExecStart: "{ path=/usr/bin/app }", SHA256: strings.Repeat("a1", 32)},
		"tmp.service": {Transient: true, ExecStart: "{ path=/bin/true }", SHA256: strings.Repeat("b2", 32)},
	}}
	h := newHarness(t, func(c *Config) { c.Units = units })
	r := &svcRig{h: h, units: units, uid: 1000}
	p, err := h.srv.partition(context.Background(), r.uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.Put(context.Background(), "app-db/value", []byte(svcCanary)); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *svcRig) enroll(t *testing.T, mutate func(*brokerapi.ServiceRequest)) brokerapi.Response {
	t.Helper()
	sr := &brokerapi.ServiceRequest{Connection: "app-db", Units: []string{"app.service"}, Scope: "system"}
	if mutate != nil {
		mutate(sr)
	}
	return r.h.send(t, r.uid, r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpServiceEnroll, Service: sr}))
}

func (r *svcRig) release(t *testing.T, uid uint32, cgroup string, capability []byte, res callerkind.Result) brokerapi.Response {
	t.Helper()
	return r.h.sendAs(t, peerAs(uid, cgroup), res, brokerapi.Request{Op: brokerapi.OpServiceRelease, Service: &brokerapi.ServiceRequest{Connection: "app-db", Capability: capability}})
}

func TestEnrollNeedsPresence(t *testing.T) {
	r := newSvcRig(t)
	resp := r.h.send(t, r.uid, brokerapi.Request{Op: brokerapi.OpServiceEnroll, Service: &brokerapi.ServiceRequest{Connection: "app-db", Units: []string{"app.service"}, Scope: "system"}})
	if resp.OK || resp.Code != brokerapi.CodePresenceRequired {
		t.Fatalf("enroll without a proof = %+v", resp)
	}
	agent := callerkind.Result{Kind: callerkind.Agent}
	req := r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpServiceEnroll, Service: &brokerapi.ServiceRequest{Connection: "app-db", Units: []string{"app.service"}, Scope: "system"}})
	if resp := r.h.sendAs(t, peerAs(r.uid, ""), agent, req); resp.OK {
		t.Fatal("an agent enrolled a unit")
	}
	if len(r.units.calls) != 0 {
		t.Fatalf("the refusals inspected units: %v", r.units.calls)
	}
}

func TestServiceEnrollRecordsHashes(t *testing.T) {
	r := newSvcRig(t)
	resp := r.enroll(t, nil)
	if !resp.OK || resp.Service == nil || len(resp.Service.Capability) != 32 {
		t.Fatalf("enroll = %+v", resp)
	}
	e, ok := r.h.srv.services().get("app-db")
	if !ok || len(e.Units) != 1 || e.Units[0].SHA256 != strings.Repeat("a1", 32) || e.Units[0].ExecStart != "{ path=/usr/bin/app }" || e.Owner != r.uid || e.Scope != "system" {
		t.Fatalf("enrollment = %+v", e)
	}
	// The capability is stored only as a keyed hash.
	raw, err := os.ReadFile(filepath.Join(r.h.state, "services.json"))
	if err != nil {
		t.Fatal(err)
	}
	cap := resp.Service.Capability
	for _, enc := range []string{string(cap), hex.EncodeToString(cap), base64.StdEncoding.EncodeToString(cap), svcCanary} {
		if strings.Contains(string(raw), enc) {
			t.Fatalf("services.json holds the capability or the value: %s", raw)
		}
	}
	if e.CapHash == "" {
		t.Fatal("no capability hash")
	}
	if n := r.h.rec.count(audit.ActionServiceEnroll); n != 1 {
		t.Fatalf("%d enroll events", n)
	}
	b, _ := json.Marshal(r.h.rec.events)
	if strings.Contains(string(b), svcCanary) || strings.Contains(string(b), hex.EncodeToString(cap)) {
		t.Fatalf("audit holds a secret: %s", b)
	}

	// Refusals: a transient unit, an unknown unit, a missing connection, a unit without a file.
	if resp := r.enroll(t, func(s *brokerapi.ServiceRequest) { s.Units = []string{"tmp.service"} }); resp.OK || !strings.Contains(resp.Error, "transient") {
		t.Fatalf("transient enroll = %+v", resp)
	}
	if resp := r.enroll(t, func(s *brokerapi.ServiceRequest) { s.Units = []string{"tmp.service"}; s.AllowTransient = true }); !resp.OK {
		t.Fatalf("--allow-transient enroll = %+v", resp)
	}
	if resp := r.enroll(t, func(s *brokerapi.ServiceRequest) { s.Units = []string{"ghost.service"} }); resp.OK {
		t.Fatal("an unknown unit was enrolled")
	}
	if resp := r.enroll(t, func(s *brokerapi.ServiceRequest) { s.Connection = "nothing-stored" }); resp.OK || resp.Code != brokerapi.CodeNotFound {
		t.Fatalf("missing connection = %+v", resp)
	}
	r.units.info["nofile.service"] = UnitInfo{ExecStart: "x", SHA256: "x"}
	if resp := r.enroll(t, func(s *brokerapi.ServiceRequest) { s.Units = []string{"nofile.service"} }); resp.OK {
		t.Fatal("a unit with no file was enrolled")
	}
	r.units.err = errors.New("no D-Bus")
	if resp := r.enroll(t, nil); resp.OK {
		t.Fatal("enrolled without being able to inspect")
	}
}

func TestServiceReleaseInEnrolledUnit(t *testing.T) {
	r := newSvcRig(t)
	cap := r.enroll(t, nil).Service.Capability
	resp := r.release(t, 1000, "/system.slice/app.service", cap, host)
	if !resp.OK || resp.Service == nil || len(resp.Service.Env) != 1 || string(resp.Service.Env[0].Value) != svcCanary || resp.Service.Env[0].Name != "APP_DB" {
		t.Fatalf("release = %+v", resp)
	}
	ev, ok := r.h.rec.last(audit.ActionRelease)
	if !ok || ev.Extra["unit"] != "app.service" || ev.Extra["caller_kind"] != "service" || ev.Extra["connection"] != "app-db" {
		t.Fatalf("release event = %+v", ev)
	}
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), svcCanary) {
		t.Fatal("the release event holds the value")
	}

	// A system account outside the broker's user range is served for this one request only.
	h2 := r.h
	srv := h2.srv
	srv.cfg.Identify = func(*net.UnixConn) (*Identity, error) {
		return &Identity{UID: 33, PID: 4242, Start: "1", Cgroup: "/system.slice/app.service", pin: okPin{}}, nil
	}
	call, stop := h2.serve(t)
	defer stop()
	var out brokerapi.Response
	call(brokerapi.Request{Op: brokerapi.OpServiceRelease, Service: &brokerapi.ServiceRequest{Connection: "app-db", Capability: cap}}, &out)
	if !out.OK || out.Service == nil || string(out.Service.Env[0].Value) != svcCanary {
		t.Fatalf("a service account's release = %+v", out)
	}
	var denied control.Response
	call(brokerapi.Request{Op: brokerapi.OpSecretList}, &denied)
	if denied.Code != control.CodeRefused || !strings.Contains(denied.Error, "may not use the broker") {
		t.Fatalf("any other request from that account = %+v", denied)
	}
	call(map[string]any{"op": "service.release", "bogus": 1}, &denied)
	if denied.Code != control.CodeRefused {
		t.Fatalf("a malformed release = %+v", denied)
	}
}

func TestServiceDeniedFromShell(t *testing.T) {
	r := newSvcRig(t)
	cap := r.enroll(t, nil).Service.Capability
	for name, cg := range map[string]string{
		"a login session": "/user.slice/user-1000.slice/session-3.scope",
		"the root slice":  "/",
		"a user manager":  "/user.slice/user-1000.slice/user@1000.service",
		"another unit":    "/system.slice/other.service",
	} {
		resp := r.release(t, 1000, cg, cap, host)
		if resp.OK || resp.Service != nil || strings.Contains(resp.Error, "unit") && strings.Contains(resp.Error, "enrolled") {
			t.Errorf("%s: %+v", name, resp)
		}
	}
	if resp := r.release(t, 1000, "/system.slice/app.service", append([]byte(nil), make([]byte, 32)...), host); resp.OK {
		t.Fatal("a wrong capability released the secret")
	}
	if resp := r.release(t, 1000, "/system.slice/app.service", cap, callerkind.Result{Kind: callerkind.Agent}); resp.OK {
		t.Fatal("an agent was released the secret")
	}
	if n := r.h.rec.count(audit.ActionSecurityBlock); n < 6 {
		t.Fatalf("%d security.block events for 6 refusals", n)
	}
	for _, e := range r.h.rec.events {
		if e.Action == audit.ActionRelease {
			t.Fatal("a release was recorded for a refusal")
		}
	}
}

func TestServiceDeniedTransient(t *testing.T) {
	r := newSvcRig(t)
	cap := r.enroll(t, nil).Service.Capability
	// The unit was enrolled as a file unit and is now transient (systemd-run replaced it).
	r.units.info["app.service"] = UnitInfo{Transient: true, ExecStart: "{ path=/usr/bin/app }", SHA256: strings.Repeat("a1", 32)}
	if resp := r.release(t, 1000, "/system.slice/app.service", cap, host); resp.OK {
		t.Fatal("a transient unit received the secret")
	}
}

func TestServiceTransientProbeAllowed(t *testing.T) {
	r := newSvcRig(t)
	cap := r.enroll(t, func(s *brokerapi.ServiceRequest) { s.Units = []string{"tmp.service"}; s.AllowTransient = true }).Service.Capability
	if resp := r.release(t, 1000, "/system.slice/tmp.service", cap, host); !resp.OK {
		t.Fatalf("an enrolled transient unit = %+v", resp)
	}
}

func TestServiceDeniedEditedUnit(t *testing.T) {
	r := newSvcRig(t)
	cap := r.enroll(t, nil).Service.Capability
	edited := r.units.info["app.service"]
	edited.SHA256 = strings.Repeat("ff", 32)
	r.units.info["app.service"] = edited
	if resp := r.release(t, 1000, "/system.slice/app.service", cap, host); resp.OK {
		t.Fatal("an edited unit received the secret")
	}
	edited.SHA256 = strings.Repeat("a1", 32)
	edited.ExecStart = "{ path=/usr/bin/evil }"
	r.units.info["app.service"] = edited
	if resp := r.release(t, 1000, "/system.slice/app.service", cap, host); resp.OK {
		t.Fatal("a unit with another ExecStart received the secret")
	}
	r.units.err = errors.New("D-Bus is gone")
	if resp := r.release(t, 1000, "/system.slice/app.service", cap, host); resp.OK {
		t.Fatal("a unit that cannot be inspected received the secret")
	}
	// Doctor sees the same change.
	r.units.err = nil
	list := r.h.send(t, r.uid, brokerapi.Request{Op: brokerapi.OpServiceList, Service: &brokerapi.ServiceRequest{}})
	if !list.OK || len(list.Service.Services) != 1 || !list.Service.Services[0].Changed || !strings.Contains(list.Service.Services[0].Detail, "ExecStart") {
		t.Fatalf("list = %+v", list)
	}
	if b, _ := json.Marshal(list); strings.Contains(string(b), hex.EncodeToString(cap)) {
		t.Fatal("the list holds the capability")
	}
}

// A user-scope blob decrypts for the user and yields only the capability. Held
// by an agent outside the unit it releases nothing.
func TestUserBlobUselessOutsideUnit(t *testing.T) {
	r := newSvcRig(t)
	cap := r.enroll(t, func(s *brokerapi.ServiceRequest) { s.Scope = "user" }).Service.Capability
	for name, cg := range map[string]string{
		"a shell in a login session": "/user.slice/user-1000.slice/session-4.scope",
		"a transient scope":          "/user.slice/user-1000.slice/user@1000.service/app.slice/run-r1.scope",
		"another user unit":          "/user.slice/user-1000.slice/user@1000.service/app.slice/other.service",
	} {
		if resp := r.release(t, 1000, cg, cap, host); resp.OK || resp.Service != nil {
			t.Errorf("%s was released the secret: %+v", name, resp)
		}
	}
	agent := callerkind.Result{Kind: callerkind.Agent}
	if resp := r.release(t, 1000, "/user.slice/user-1000.slice/user@1000.service/app.slice/app.service", cap, agent); resp.OK {
		t.Fatal("an agent holding the capability was released the secret")
	}
}

func TestServiceScopesAndRevoke(t *testing.T) {
	r := newSvcRig(t)
	// A user-scope enrollment is released only to that user's own manager.
	cap := r.enroll(t, func(s *brokerapi.ServiceRequest) { s.Scope = "user" }).Service.Capability
	user := "/user.slice/user-1000.slice/user@1000.service/app.slice/app.service"
	if resp := r.release(t, 1000, user, cap, host); !resp.OK {
		t.Fatalf("user unit = %+v", resp)
	}
	if resp := r.release(t, 1001, user, cap, host); resp.OK {
		t.Fatal("another user's process received the secret")
	}
	if resp := r.release(t, 1000, "/system.slice/app.service", cap, host); resp.OK {
		t.Fatal("a system unit received a user-scope secret")
	}
	if got := r.units.calls[len(r.units.calls)-1]; !strings.HasPrefix(got, "user:") {
		t.Fatalf("inspection scope = %s", got)
	}

	// Revoking one unit leaves the others; revoking the last removes the enrollment.
	cap = r.enroll(t, func(s *brokerapi.ServiceRequest) {
		s.Units = []string{"app.service", "tmp.service"}
		s.AllowTransient = true
	}).Service.Capability
	revoke := func(unit string) brokerapi.Response {
		return r.h.send(t, r.uid, r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpServiceRevoke, Service: &brokerapi.ServiceRequest{Connection: "app-db", Unit: unit}}))
	}
	if resp := revoke("tmp.service"); !resp.OK {
		t.Fatalf("revoke = %+v", resp)
	}
	if resp := r.release(t, 1000, "/system.slice/tmp.service", cap, host); resp.OK {
		t.Fatal("a revoked unit received the secret")
	}
	if resp := r.release(t, 1000, "/system.slice/app.service", cap, host); !resp.OK {
		t.Fatalf("the remaining unit = %+v", resp)
	}
	if resp := revoke("tmp.service"); resp.OK {
		t.Fatal("revoking twice succeeded")
	}
	if resp := revoke(""); !resp.OK {
		t.Fatalf("revoke all = %+v", resp)
	}
	if _, ok := r.h.srv.services().get("app-db"); ok {
		t.Fatal("the enrollment survived revoking every unit")
	}
	if resp := r.h.send(t, r.uid, brokerapi.Request{Op: brokerapi.OpServiceRevoke, Service: &brokerapi.ServiceRequest{Connection: "app-db"}}); resp.OK {
		t.Fatal("revoke without a proof")
	}
	if n := r.h.rec.count(audit.ActionServiceRevoke); n != 2 {
		t.Fatalf("%d revoke events", n)
	}
	if resp := r.h.send(t, 1001, r.h.proven(t, 1001, brokerapi.Request{Op: brokerapi.OpServiceRevoke, Service: &brokerapi.ServiceRequest{Connection: "app-db"}})); resp.OK {
		t.Fatal("another user revoked")
	}
}

func TestSystemctlInspector(t *testing.T) {
	files := map[string]string{"/etc/app.service": "[Service]\nExecStart=/bin/app\n", "/etc/app.service.d/o.conf": "[Service]\nEnvironment=A=1\n"}
	var seen []string
	in := systemctlInspector{
		run: func(_ context.Context, args ...string) ([]byte, error) {
			seen = args
			return []byte("Transient=no\nFragmentPath=/etc/app.service\nDropInPaths=/etc/app.service.d/o.conf\nExecStart={ path=/bin/app ; argv[]=/bin/app }\n"), nil
		},
		readFile: func(p string) ([]byte, error) {
			if b, ok := files[p]; ok {
				return []byte(b), nil
			}
			return nil, os.ErrNotExist
		},
	}
	info, err := in.Inspect(context.Background(), "system", 1000, "app.service")
	if err != nil || info.Transient || info.FragmentPath != "/etc/app.service" || len(info.DropIns) != 1 || info.SHA256 == "" || !strings.Contains(info.ExecStart, "/bin/app") {
		t.Fatalf("info = %+v %v", info, err)
	}
	if strings.Contains(strings.Join(seen, " "), "--user") {
		t.Fatalf("system scope args = %v", seen)
	}
	first := info.SHA256
	files["/etc/app.service.d/o.conf"] = "[Service]\nEnvironment=A=2\n"
	if again, _ := in.Inspect(context.Background(), "system", 1000, "app.service"); again.SHA256 == first {
		t.Fatal("a drop-in change must change the digest")
	}
	if _, err := in.Inspect(context.Background(), "user", 1234, "app.service"); err != nil || strings.Join(seen, " ") == "" || !strings.Contains(strings.Join(seen, " "), "--user --machine=1234@.host") {
		t.Fatalf("user scope args = %v %v", seen, err)
	}
	delete(files, "/etc/app.service")
	if _, err := in.Inspect(context.Background(), "system", 1000, "app.service"); err == nil {
		t.Fatal("an unreadable unit file must be an error")
	}
	bad := systemctlInspector{run: func(context.Context, ...string) ([]byte, error) { return []byte("FragmentPath=/x\n"), nil }}
	if _, err := bad.Inspect(context.Background(), "system", 0, "a.service"); err == nil {
		t.Fatal("no Transient property must be an error")
	}
	failing := systemctlInspector{run: func(context.Context, ...string) ([]byte, error) { return nil, errors.New("boom") }}
	if _, err := failing.Inspect(context.Background(), "system", 0, "a.service"); err == nil {
		t.Fatal("a systemctl failure must be an error")
	}
}

func TestUnitOfCgroup(t *testing.T) {
	cases := map[string]struct {
		unit string
		user bool
		ok   bool
	}{
		"/system.slice/app.service":                                         {"app.service", false, true},
		"/system.slice/app.service/sub":                                     {"app.service", false, true},
		"/user.slice/user-1000.slice/user@1000.service/app.slice/x.service": {"x.service", true, true},
		"/user.slice/user-1000.slice/user@1000.service":                     {"", false, false},
		"/user.slice/user-1000.slice/session-2.scope":                       {"", false, false},
		"": {"", false, false},
	}
	for cg, want := range cases {
		unit, user, ok := unitOfCgroup(cg)
		if unit != want.unit || user != want.user || ok != want.ok {
			t.Errorf("%q = %q %v %v, want %+v", cg, unit, user, ok, want)
		}
	}
	if envName("my-app.db") != "MY_APP_DB" {
		t.Fatal(envName("my-app.db"))
	}
}

func TestServiceReleaseUsesTheProviderContract(t *testing.T) {
	r := newSvcRig(t)
	p, _ := r.h.srv.partition(context.Background(), r.uid)
	ctx := context.Background()
	s := storeSecrets{p.store}
	if err := registry.Register(registry.ConnectionTemplate{
		Provider: "svc-demo", DisplayName: "Service demo", Category: "ai",
		InjectionRules: []registry.InjectionRule{{EnvVar: "SVC_DEMO_KEY", Source: "api_key"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.serviceEnv(ctx, "svc-demo"); err == nil {
		t.Fatal("a provider connection with no stored field must fail")
	}
	if _, err := p.store.Put(ctx, "default/ai/svc-demo/api_key", []byte(svcCanary+"-ai")); err != nil {
		t.Fatal(err)
	}
	env, err := s.serviceEnv(ctx, "svc-demo")
	if err != nil || len(env) != 1 || env[0].Name != "SVC_DEMO_KEY" || string(env[0].Value) != svcCanary+"-ai" {
		t.Fatalf("env = %+v %v", env, err)
	}
	if _, err := s.credentialPaths(ctx, "missing"); err == nil {
		t.Fatal("missing connection")
	}
}
