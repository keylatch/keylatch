//go:build unix

package brokerd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/callerkind"
	keysync "github.com/keylatch/keylatch/internal/sync"
	"github.com/keylatch/keylatch/internal/sync/targets"
)

var syncCanary = "canary" + "-daemon-" + "5e90"

const syncManifest = `version: 1
targets:
  web:   {type: vercel, project: prj_1, credential: vercel-deploy}
  local: {type: env-file, path: .env.local}
vars:
  - name: DATABASE_URL
    from: {connection: app-db, field: url}
    to: {web: [production, preview], local: [file]}
`

type fakeRemote struct {
	id        string
	entries   map[string]*keysync.Remote
	values    map[string]string
	writes    int
	lists     int
	clock     time.Time
	nextEntry int
}

func newFakeRemote(id string) *fakeRemote {
	return &fakeRemote{id: id, entries: map[string]*keysync.Remote{}, values: map[string]string{}, clock: time.Unix(1_800_000_000, 0)}
}

func (f *fakeRemote) ID() string { return f.id }

func (f *fakeRemote) List(context.Context) ([]keysync.Remote, error) {
	f.lists++
	var out []keysync.Remote
	for _, r := range f.entries {
		out = append(out, *r)
	}
	return out, nil
}

func (f *fakeRemote) Write(_ context.Context, name string, v []byte, envs []string, sensitive bool) error {
	f.writes++
	f.clock = f.clock.Add(time.Second)
	typ := "encrypted"
	if sensitive {
		typ = "sensitive"
	}
	f.nextEntry++
	f.entries[name] = &keysync.Remote{ID: name, Name: name, Environments: slices.Clone(envs), Type: typ, UpdatedAt: f.clock}
	f.values[name] = string(v)
	return nil
}

func (f *fakeRemote) Delete(_ context.Context, r keysync.Remote) error {
	delete(f.entries, r.Name)
	return nil
}

func (f *fakeRemote) Readback(context.Context, keysync.Remote) ([]byte, bool, error) {
	return nil, false, nil
}

// countingStore counts reads of the partition's store.
type countingStore struct {
	secretStore
	reads int
}

func (c *countingStore) Get(ctx context.Context, p string) ([]byte, backend.Meta, error) {
	c.reads++
	return c.secretStore.Get(ctx, p)
}

func (c *countingStore) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	c.reads++
	return c.secretStore.List(ctx, prefix)
}

type syncRig struct {
	h     *harness
	web   *fakeRemote
	store *countingStore
	uid   uint32
}

func newSyncRig(t *testing.T) *syncRig {
	t.Helper()
	web := newFakeRemote("vercel:prj_1")
	h := newHarness(t, func(c *Config) {
		c.Sync.Target = func(name string, _ keysync.Target, _ targets.Token) (keysync.TargetClient, bool) {
			if name == "web" {
				return web, true
			}
			return nil, false
		}
		c.Sync.Probe = func(context.Context, string, []byte) error { return nil }
	})
	r := &syncRig{h: h, web: web, uid: 1000}
	p, err := h.srv.partition(context.Background(), r.uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.Put(context.Background(), "app-db/url", []byte(syncCanary+"-db")); err != nil {
		t.Fatal(err)
	}
	r.store = &countingStore{secretStore: p.store}
	p.syncStore = r.store
	return r
}

func (r *syncRig) req(op brokerapi.Op, mutate func(*brokerapi.SyncRequest)) brokerapi.Request {
	s := &brokerapi.SyncRequest{Manifest: []byte(syncManifest), Root: "/repo", EnvKeys: map[string][]string{"local": {"OTHER"}}}
	if mutate != nil {
		mutate(s)
	}
	return brokerapi.Request{Op: op, Sync: s}
}

func TestSyncApplyNeedsPresence(t *testing.T) {
	r := newSyncRig(t)
	resp := r.h.send(t, r.uid, r.req(brokerapi.OpSyncApply, func(s *brokerapi.SyncRequest) { s.EnvKeys = nil }))
	if resp.OK || resp.Code != brokerapi.CodePresenceRequired {
		t.Fatalf("apply without a proof = %+v", resp)
	}
	if r.web.writes != 0 {
		t.Fatal("a target was written without presence")
	}
	// A proof for another request does not carry over.
	other := r.h.proven(t, r.uid, r.req(brokerapi.OpSyncApply, func(s *brokerapi.SyncRequest) { s.Prune = true }))
	swapped := r.req(brokerapi.OpSyncApply, nil)
	swapped.Proof = other.Proof
	if resp := r.h.send(t, r.uid, swapped); resp.OK {
		t.Fatal("a proof for a --prune request approved another request")
	}
}

func TestSyncAgentRefusedBeforeBackendRead(t *testing.T) {
	r := newSyncRig(t)
	agent := callerkind.Result{Kind: callerkind.Agent, Reasons: []string{"signals"}}
	req := r.h.proven(t, r.uid, r.req(brokerapi.OpSyncApply, nil))
	before := r.store.reads
	resp := r.h.sendAs(t, peerAs(r.uid, ""), agent, req)
	if resp.OK || resp.ExitCode == 0 {
		t.Fatalf("an agent applied: %+v", resp)
	}
	if r.store.reads != before || r.web.lists != 0 || r.web.writes != 0 {
		t.Fatalf("the refusal came after a read: store reads %d, target lists %d", r.store.reads-before, r.web.lists)
	}
	if r.h.rec.count(audit.ActionSecurityBlock) == 0 {
		t.Fatal("the refusal was not audited")
	}
	rot := r.h.sendAs(t, peerAs(r.uid, ""), agent, r.req(brokerapi.OpSyncRotate, func(s *brokerapi.SyncRequest) { s.Name = "DATABASE_URL" }))
	if rot.OK || r.store.reads != before {
		t.Fatalf("an agent rotated: %+v", rot)
	}
	// An agent may ask what differs: no value is read out or returned.
	diff := r.h.sendAs(t, peerAs(r.uid, ""), agent, r.req(brokerapi.OpSyncDrift, nil))
	if !diff.OK || diff.Sync == nil || !diff.Sync.Drift {
		t.Fatalf("an agent's drift = %+v", diff)
	}
}

func TestSyncAuditOneEventPerWriteNoValue(t *testing.T) {
	r := newSyncRig(t)
	req := r.h.proven(t, r.uid, r.req(brokerapi.OpSyncApply, func(s *brokerapi.SyncRequest) { s.EnvKeys = nil }))
	// Only the vercel target is applied here: the env file target has no descriptors.
	req.Sync.Manifest = []byte(strings.Replace(syncManifest, ", local: [file]", "", 1))
	req = r.h.proven(t, r.uid, brokerapi.Request{Op: req.Op, Sync: req.Sync})
	resp := r.h.send(t, r.uid, req)
	if !resp.OK || resp.Sync == nil {
		t.Fatalf("apply = %+v", resp)
	}
	if r.web.writes != 1 || r.web.values["DATABASE_URL"] != syncCanary+"-db" {
		t.Fatalf("writes = %d", r.web.writes)
	}
	if n := r.h.rec.count(audit.ActionSyncWrite); n != 2 {
		t.Fatalf("%d sync.write events for 2 entries", n)
	}
	ev, _ := r.h.rec.last(audit.ActionSyncWrite)
	for _, k := range []string{"connection", "target", "environment", "name", "caller_kind", "presence", "outcome"} {
		if _, ok := ev.Extra[k]; !ok {
			t.Errorf("event lacks %q: %v", k, ev.Extra)
		}
	}
	b, _ := json.Marshal(r.h.rec.events)
	if strings.Contains(string(b), syncCanary) {
		t.Fatalf("audit holds a value: %s", b)
	}
	body, _ := json.Marshal(resp)
	if strings.Contains(string(body), syncCanary) {
		t.Fatalf("response holds a value: %s", body)
	}

	// A second apply writes nothing.
	again := r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncApply, Sync: req.Sync})
	if resp := r.h.send(t, r.uid, again); !resp.OK || r.web.writes != 1 {
		t.Fatalf("second apply: %+v, writes %d", resp, r.web.writes)
	}
	state, _ := os.ReadFile(filepath.Join(r.h.srv.PartitionDir(r.uid), "config", "sync-state.json"))
	if len(state) == 0 || strings.Contains(string(state), syncCanary) {
		t.Fatalf("the state file is empty or holds a value: %s", state)
	}
}

func TestSyncRotateThroughDaemon(t *testing.T) {
	r := newSyncRig(t)
	vercelOnly := strings.Replace(syncManifest, ", local: [file]", "", 1)
	apply := r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncApply, Sync: &brokerapi.SyncRequest{Manifest: []byte(vercelOnly)}})
	if resp := r.h.send(t, r.uid, apply); !resp.OK {
		t.Fatalf("apply: %+v", resp)
	}
	p, _ := r.h.srv.partition(context.Background(), r.uid)
	if _, err := p.store.Put(context.Background(), "app-db/url", []byte(syncCanary+"-v2")); err != nil {
		t.Fatal(err)
	}
	rot := r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncRotate, Sync: &brokerapi.SyncRequest{Manifest: []byte(vercelOnly), Name: "DATABASE_URL"}})
	resp := r.h.send(t, r.uid, rot)
	if !resp.OK || r.web.values["DATABASE_URL"] != syncCanary+"-v2" {
		t.Fatalf("rotate = %+v", resp)
	}
	if r.h.rec.count(audit.ActionSyncRotateComplete) != 1 || r.h.rec.count(audit.ActionSyncRotateVerify) != 2 {
		t.Fatalf("events: complete %d verify %d", r.h.rec.count(audit.ActionSyncRotateComplete), r.h.rec.count(audit.ActionSyncRotateVerify))
	}
	// A rotation with a source that did not change is refused with the entries so far.
	again := r.h.proven(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncRotate, Sync: &brokerapi.SyncRequest{Manifest: []byte(vercelOnly), Name: "DATABASE_URL"}})
	if resp := r.h.send(t, r.uid, again); resp.OK {
		t.Fatal("rotating an unchanged source succeeded")
	}
}

func TestSyncRejectsBadManifestAndUnsignedPolicy(t *testing.T) {
	r := newSyncRig(t)
	resp := r.h.send(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncDiff, Sync: &brokerapi.SyncRequest{Manifest: []byte("version: 1\nnope: 2\n")}})
	if resp.OK || resp.Code != brokerapi.CodeBadRequest || !strings.Contains(resp.Error, "nope") {
		t.Fatalf("bad manifest = %+v", resp)
	}
	resp = r.h.send(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncDiff, Sync: &brokerapi.SyncRequest{Manifest: []byte(syncManifest)}})
	if !resp.OK {
		t.Fatalf("diff = %+v", resp)
	}
	// A vercel link the client did not resolve is an error, not an empty project.
	link := strings.Replace(syncManifest, "project: prj_1", "link: .vercel/project.json", 1)
	r.h.srv.cfg.Sync.Target = nil
	resp = r.h.send(t, r.uid, brokerapi.Request{Op: brokerapi.OpSyncDiff, Sync: &brokerapi.SyncRequest{Manifest: []byte(link)}})
	if resp.OK || !strings.Contains(resp.Error, "link") {
		t.Fatalf("unresolved link = %+v", resp)
	}
}

func TestStoreSecretsResolution(t *testing.T) {
	r := newSyncRig(t)
	p, _ := r.h.srv.partition(context.Background(), r.uid)
	ctx := context.Background()
	for path, v := range map[string]string{
		"vercel-deploy/token": "tok-1", "plain": "p", "multi/value": "m",
		"default/cloud/aws/secret": "a", "other/cloud/aws/secret": "b", "default/ci/gh/api_key": "k",
	} {
		if _, err := p.store.Put(ctx, path, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	s := storeSecrets{p.store}
	if tok, err := s.credential(ctx, "vercel-deploy"); err != nil || tok != "tok-1" {
		t.Fatalf("credential = %q %v", tok, err)
	}
	if v, err := s.Value(ctx, "plain", ""); err != nil || string(v) != "p" {
		t.Fatalf("exact path = %q %v", v, err)
	}
	if v, err := s.Value(ctx, "multi", ""); err != nil || string(v) != "m" {
		t.Fatalf("connection/value = %q %v", v, err)
	}
	if v, err := s.Value(ctx, "gh", "api_key"); err != nil || string(v) != "k" {
		t.Fatalf("suffix match = %q %v", v, err)
	}
	if _, err := s.Value(ctx, "aws", "secret"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous = %v", err)
	}
	if _, err := s.Value(ctx, "missing", "x"); !errors.Is(err, keysync.ErrNoSecret) {
		t.Fatalf("missing = %v", err)
	}
	if _, err := s.credential(ctx, "missing"); err == nil {
		t.Fatal("missing credential")
	}
	if _, err := s.Previous(ctx, "app-db", "url"); !errors.Is(err, keysync.ErrNoPrevious) {
		t.Fatalf("no previous = %v", err)
	}
	if err := s.Remember(ctx, "app-db", "url", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Previous(ctx, "app-db", "url"); err != nil || string(v) != "v1" {
		t.Fatalf("previous = %q %v", v, err)
	}
}

func TestSyncStateKeyedAndPersistent(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	st := newSyncState(dir, func() ([]byte, error) { return slices.Clone(key), nil })
	if _, ok := st.Written("t", "e", "N"); ok {
		t.Fatal("empty state has a record")
	}
	mac := st.MAC("t", "e", "N", []byte("v"))
	if mac == st.MAC("t", "e", "N", []byte("w")) || mac == st.MAC("t", "e2", "N", []byte("v")) || mac == st.MAC("t2", "e", "N", []byte("v")) {
		t.Fatal("the MAC must bind identity and value")
	}
	if err := st.Record("t", "e", "N", mac, time.Unix(5, 0)); err != nil {
		t.Fatal(err)
	}
	st2 := newSyncState(dir, func() ([]byte, error) { return slices.Clone(key), nil })
	if w, ok := st2.Written("t", "e", "N"); !ok || w.MAC != mac || !w.RemoteAt.Equal(time.Unix(5, 0)) {
		t.Fatalf("reload = %+v %v", w, ok)
	}
	if err := st2.Forget("t", "e", "N"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st2.Written("t", "e", "N"); ok {
		t.Fatal("forgotten record survived")
	}
	bad := newSyncState(dir, func() ([]byte, error) { return nil, errors.New("locked") })
	if bad.MAC("a", "b", "c", []byte("v")) != "unavailable" {
		t.Fatal("a missing key must not yield a usable MAC")
	}
	if err := os.WriteFile(filepath.Join(dir, "sync-state.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := newSyncState(dir, func() ([]byte, error) { return key, nil })
	if _, ok := broken.Written("t", "e", "N"); ok {
		t.Fatal("a corrupt state file produced a record")
	}
	if err := broken.Record("t", "e", "N", "m", time.Now()); err == nil {
		t.Fatal("a corrupt state file was overwritten")
	}
}

// The env file travels as descriptors: the daemon reads the existing file and
// writes the merged content into the temp file, keeping unmanaged lines.
func TestSyncEnvFileAtomic0600(t *testing.T) {
	r := newSyncRig(t)
	dir := t.TempDir()
	target := filepath.Join(dir, ".env.local")
	if err := os.WriteFile(target, []byte("# mine\nKEEP=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	existing, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	temp, err := os.OpenFile(filepath.Join(dir, ".env.local.tmp"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer temp.Close()

	server, client := pair(t)
	req := r.h.proven(t, r.uid, r.req(brokerapi.OpSyncApply, func(s *brokerapi.SyncRequest) {
		s.EnvFiles, s.EnvKeys = []string{"local"}, nil
		s.Manifest = []byte(strings.Replace(syncManifest, "web: [production, preview], ", "", 1))
		s.Manifest = []byte(strings.Replace(string(s.Manifest), "  web:   {type: vercel, project: prj_1, credential: vercel-deploy}\n", "", 1))
	}))
	done := make(chan brokerapi.Response, 1)
	go func() {
		p, _ := r.h.srv.partition(context.Background(), r.uid)
		a := &admin{s: r.h.srv, p: p}
		done <- a.dispatch(context.WithValue(context.Background(), connCtxKey{}, server), peerAs(r.uid, ""), host, req)
	}()
	line := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := client.Read(line)
	if err != nil || !strings.Contains(string(line[:n]), brokerapi.CodeSendFiles) {
		t.Fatalf("interim frame %q: %v", line[:n], err)
	}
	rights := syscall.UnixRights(int(existing.Fd()), int(temp.Fd()))
	if _, _, err := client.WriteMsgUnix([]byte{0}, rights, nil); err != nil {
		t.Fatal(err)
	}
	resp := <-done
	if !resp.OK {
		t.Fatalf("apply = %+v", resp)
	}
	merged, _ := os.ReadFile(temp.Name())
	want := "# mine\nKEEP=1\nDATABASE_URL=" + syncCanary + "-db\n"
	if string(merged) != want {
		t.Fatalf("merged content:\n%q\nwant\n%q", merged, want)
	}
	if info, _ := os.Stat(temp.Name()); info.Mode().Perm() != 0o600 {
		t.Fatalf("temp mode = %v", info.Mode().Perm())
	}
	if orig, _ := os.ReadFile(target); string(orig) != "# mine\nKEEP=1\n" {
		t.Fatal("the existing file was modified in place")
	}
	b, _ := json.Marshal(resp)
	if strings.Contains(string(b), syncCanary) {
		t.Fatal("the response carries the value")
	}
}

func TestSyncEnvFileRefusals(t *testing.T) {
	r := newSyncRig(t)
	envOnly := func(s *brokerapi.SyncRequest) {
		s.EnvFiles, s.EnvKeys = []string{"local"}, nil
		m := strings.Replace(syncManifest, "web: [production, preview], ", "", 1)
		s.Manifest = []byte(strings.Replace(m, "  web:   {type: vercel, project: prj_1, credential: vercel-deploy}\n", "", 1))
	}
	// Without a connection to receive them, descriptors cannot be accepted.
	req := r.h.proven(t, r.uid, r.req(brokerapi.OpSyncApply, envOnly))
	if resp := r.h.send(t, r.uid, req); resp.OK {
		t.Fatal("descriptors accepted without a socket")
	}

	// A client that sends the wrong number of descriptors is refused.
	server, client := pair(t)
	req = r.h.proven(t, r.uid, r.req(brokerapi.OpSyncApply, envOnly))
	done := make(chan brokerapi.Response, 1)
	go func() {
		p, _ := r.h.srv.partition(context.Background(), r.uid)
		done <- (&admin{s: r.h.srv, p: p}).dispatch(context.WithValue(context.Background(), connCtxKey{}, server), peerAs(r.uid, ""), host, req)
	}()
	buf := make([]byte, 4096)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(buf); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(os.DevNull)
	defer f.Close()
	if _, _, err := client.WriteMsgUnix([]byte{0}, syscall.UnixRights(int(f.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if resp := <-done; resp.OK {
		t.Fatal("one descriptor accepted for two")
	}

	// A temp file that is not empty is refused.
	dir := t.TempDir()
	full := filepath.Join(dir, "full")
	_ = os.WriteFile(full, []byte("x"), 0o600)
	tf, _ := os.OpenFile(full, os.O_WRONLY, 0)
	defer tf.Close()
	server, client = pair(t)
	req = r.h.proven(t, r.uid, r.req(brokerapi.OpSyncApply, envOnly))
	go func() {
		p, _ := r.h.srv.partition(context.Background(), r.uid)
		done <- (&admin{s: r.h.srv, p: p}).dispatch(context.WithValue(context.Background(), connCtxKey{}, server), peerAs(r.uid, ""), host, req)
	}()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(buf); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.WriteMsgUnix([]byte{0}, syscall.UnixRights(int(f.Fd()), int(tf.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if resp := <-done; resp.OK || !strings.Contains(resp.Error, "empty regular file") {
		t.Fatalf("non-empty temp = %+v", resp)
	}
}

func TestHTTPSProbeRefusals(t *testing.T) {
	ctx := context.Background()
	if err := httpsProbe(ctx, "http://example.test/", []byte("v")); err == nil {
		t.Fatal("a plain http probe was sent")
	}
	// Loopback is inside the deny ranges, so a local listener cannot be probed.
	if err := httpsProbe(ctx, "https://127.0.0.1:1/", []byte("v")); err == nil {
		t.Fatal("a loopback probe was sent")
	}
}
