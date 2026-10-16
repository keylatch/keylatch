package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// canary is built by concatenation so no credential-shaped literal exists.
var canary = "canary" + "-value-" + "9f2c"

type memStore struct {
	mu     sync.Mutex
	vals   map[string][]byte
	puts   int
	getErr error
	putErr error
}

func newMem() *memStore { return &memStore{vals: map[string][]byte{}} }

func (m *memStore) Get(_ context.Context, p string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	v, ok := m.vals[p]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (m *memStore) Put(_ context.Context, p string, v []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	m.puts++
	m.vals[p] = append([]byte(nil), v...)
	return nil
}

const secretToolOut = `[/org/freedesktop/secrets/collection/login/1]
label = Stripe
secret = %s
created = 2026-01-01
attribute.service = pay
attribute.account = stripe

[/org/freedesktop/secrets/collection/login/2]
label = Twilio
secret = %s
attribute.service = pay
`

func testEnv(t *testing.T) (Env, string) {
	t.Helper()
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(p, body string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(proj, ".env"), "# comment\nexport API_KEY='"+canary+"'\nDB_URL=\""+canary+"-db\"\nbad line\n=novalue\n")
	write(filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n    oauth_token: "+canary+"\n    user: me\n")
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "secret-tool":
			if args[0] == "search" {
				return []byte(strings.NewReplacer("%s", canary).Replace(secretToolOut)), nil
			}
			return []byte(canary + "-ss\n"), nil
		case "gh":
			return []byte(canary + "-gh\n"), nil
		case "bw", "op", "security":
			return []byte(canary + "-" + name + "\n"), nil
		}
		return nil, errors.New("unexpected " + name)
	}
	return Env{Home: home, GOOS: "linux", Run: run}, home
}

func testMap(t *testing.T) Map {
	t.Helper()
	m, err := ParseMap([]byte(`version: 1
collections: {apps: app-secrets}
sources:
  - {type: env-file, namespace: apps, glob: "~/proj/.env*"}
  - {type: secret-service, namespace: pay, service: pay}
  - {type: keychain, namespace: mac, service: svc, accounts: [one]}
  - {type: gh, namespace: github}
  - {type: password-manager, namespace: pm, manager: bw, items: ["My Item"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInventoryHasNoValues(t *testing.T) {
	env, _ := testEnv(t)
	plan, err := Inventory(context.Background(), testMap(t), env)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(plan)
	if strings.Contains(string(b), canary) {
		t.Fatalf("inventory leaked a value: %s", b)
	}
	paths := map[string]string{}
	for _, it := range plan.Items {
		paths[it.Path] = it.Source
	}
	for _, want := range []string{"app-secrets/api_key", "app-secrets/db_url", "pay/stripe", "pay/twilio", "mac/one", "github/gh-github.com", "pm/my-item"} {
		if _, ok := paths[want]; !ok {
			t.Errorf("missing %s in %v", want, paths)
		}
	}
	again, _ := Inventory(context.Background(), testMap(t), env)
	if len(again.Items) != len(plan.Items) {
		t.Fatal("inventory is not stable")
	}
}

func TestInventoryErrors(t *testing.T) {
	env, _ := testEnv(t)
	m := testMap(t)
	failing := env
	failing.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := Inventory(context.Background(), m, failing); err == nil {
		t.Fatal("secret-tool failure not reported")
	}
	none := env
	none.Run = nil
	if _, err := Inventory(context.Background(), m, none); err == nil {
		t.Fatal("missing runner not reported")
	}
	bad := env
	bad.ReadFile = func(string) ([]byte, error) { return []byte(":\n - [\n"), nil }
	if _, err := Inventory(context.Background(), Map{Version: 1, Sources: []SourceSpec{{Type: SourceGitHubCLI, Namespace: "gh"}}}, bad); err == nil {
		t.Fatal("malformed hosts file not reported")
	}
	globErr := env
	globErr.Glob = func(string) ([]string, error) { return nil, errors.New("glob") }
	if _, err := Inventory(context.Background(), m, globErr); err == nil {
		t.Fatal("glob failure not reported")
	}
	// A host filter keeps only the named hosts.
	filtered := Map{Version: 1, Sources: []SourceSpec{{Type: SourceGitHubCLI, Namespace: "gh", Hosts: []string{"example.org"}}}}
	p, err := Inventory(context.Background(), filtered, env)
	if err != nil || len(p.Items) != 0 {
		t.Fatalf("host filter: %v %v", p, err)
	}
}

func TestParseMapValidation(t *testing.T) {
	for name, doc := range map[string]string{
		"version":     "version: 2\nsources: [{type: gh, namespace: a}]",
		"no sources":  "version: 1\nsources: []",
		"namespace":   "version: 1\nsources: [{type: gh, namespace: 'Bad Ns'}]",
		"unknown key": "version: 1\nsources: [{type: gh, namespace: a, nope: 1}]",
		"type":        "version: 1\nsources: [{type: ftp, namespace: a}]",
		"env glob":    "version: 1\nsources: [{type: env-file, namespace: a}]",
		"ss service":  "version: 1\nsources: [{type: secret-service, namespace: a}]",
		"keychain":    "version: 1\nsources: [{type: keychain, namespace: a, service: s}]",
		"pm":          "version: 1\nsources: [{type: password-manager, namespace: a, manager: x, items: [i]}]",
		"collection":  "version: 1\ncollections: {'Bad Ns': c}\nsources: [{type: gh, namespace: a}]",
		"yaml":        "version: [",
	} {
		if _, err := ParseMap([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsePlan(t *testing.T) {
	good := `{"version":1,"items":[{"name":"a","source":"gh","ref":"gh:h","path":"x/a"}]}`
	if _, err := ParsePlan([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"version":   `{"version":2,"items":[]}`,
		"missing":   `{"version":1,"items":[{"name":"a"}]}`,
		"duplicate": `{"version":1,"items":[{"name":"a","source":"gh","ref":"r","path":"p"},{"name":"b","source":"gh","ref":"r","path":"p"}]}`,
		"unknown":   `{"version":1,"items":[],"x":1}`,
	} {
		if _, err := ParsePlan([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if SafeName("  ") != "item" || SafeName("A b/C") != "a-b-c" {
		t.Fatal("SafeName")
	}
}

func inventoryPlan(t *testing.T) (Plan, Env) {
	t.Helper()
	env, _ := testEnv(t)
	plan, err := Inventory(context.Background(), testMap(t), env)
	if err != nil {
		t.Fatal(err)
	}
	return plan, env
}

func TestImportIdempotent(t *testing.T) {
	plan, env := inventoryPlan(t)
	st := newMem()
	first := Import(context.Background(), plan, env, st, ImportOptions{})
	if first.Failed != 0 || first.Written != len(plan.Items) {
		t.Fatalf("first import: %+v", first)
	}
	puts := st.puts
	second := Import(context.Background(), plan, env, st, ImportOptions{})
	if second.Written != 0 || second.Unchanged != len(plan.Items) || st.puts != puts {
		t.Fatalf("second import wrote again: %+v puts %d -> %d", second, puts, st.puts)
	}
	b, _ := json.Marshal(second)
	if strings.Contains(string(b), canary) {
		t.Fatal("result leaked a value")
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	plan, env := inventoryPlan(t)
	st := newMem()
	res := Import(context.Background(), plan, env, st, ImportOptions{DryRun: true})
	if st.puts != 0 || len(st.vals) != 0 || res.Written != 0 || !res.DryRun {
		t.Fatalf("dry run wrote: %+v", res)
	}
	for _, it := range res.Items {
		if it.Outcome != OutcomeWouldWrite {
			t.Fatalf("outcome %q", it.Outcome)
		}
	}
}

func TestImportFailures(t *testing.T) {
	plan, env := inventoryPlan(t)
	st := newMem()
	st.putErr = errors.New("denied")
	if r := Import(context.Background(), plan, env, st, ImportOptions{}); r.Failed != len(plan.Items) {
		t.Fatalf("put failures: %+v", r)
	}
	st = newMem()
	st.getErr = errors.New("locked")
	if r := Import(context.Background(), plan, env, st, ImportOptions{}); r.Failed != len(plan.Items) {
		t.Fatalf("get failures: %+v", r)
	}
	empty := env
	empty.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	r := Import(context.Background(), Plan{Version: 1, Items: []PlanItem{{Name: "g", Source: "gh", Ref: "gh:h", Path: "x/g"}}}, empty, newMem(), ImportOptions{})
	if r.Failed != 1 {
		t.Fatalf("empty value accepted: %+v", r)
	}
	bad := Import(context.Background(), Plan{Version: 1, Items: []PlanItem{{Name: "g", Source: "x", Ref: "zz:1", Path: "x/g"}}}, env, newMem(), ImportOptions{})
	if bad.Failed != 1 {
		t.Fatal("unknown reference accepted")
	}
	norun := env
	norun.Run = nil
	if r := Import(context.Background(), Plan{Version: 1, Items: []PlanItem{{Name: "g", Source: "gh", Ref: "gh:h", Path: "x/g"}}}, norun, newMem(), ImportOptions{}); r.Failed != 1 {
		t.Fatal("missing runner accepted")
	}
	failing := env
	failing.Run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("stderr " + canary) }
	r = Import(context.Background(), Plan{Version: 1, Items: []PlanItem{{Name: "g", Source: "gh", Ref: "gh:h", Path: "x/g"}}}, failing, newMem(), ImportOptions{})
	if strings.Contains(r.Items[0].Error, canary) {
		t.Fatal("tool error text reached the result")
	}
	gone := Import(context.Background(), Plan{Version: 1, Items: []PlanItem{{Name: "K", Source: "env-file", Ref: "env:" + filepath.Join(t.TempDir(), "nope") + "#K", Path: "x/k"}}}, env, newMem(), ImportOptions{})
	if gone.Failed != 1 {
		t.Fatal("missing env file accepted")
	}
}

func fastKDF(t *testing.T) KDF {
	t.Helper()
	k, err := NewKDF()
	if err != nil {
		t.Fatal(err)
	}
	k.Time, k.MemoryKiB, k.Threads = 2, 19*1024, 1
	return k
}

func TestVerifyDetectsChange(t *testing.T) {
	plan, env := inventoryPlan(t)
	st := newMem()
	kdf := fastKDF(t)
	key, err := kdf.Key([]byte("recovery passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	res := Import(context.Background(), plan, env, st, ImportOptions{Key: key, KDF: kdf})
	if res.Manifest == nil || len(res.Manifest.Items) != len(plan.Items) {
		t.Fatalf("manifest: %+v", res.Manifest)
	}
	raw, _ := json.Marshal(res.Manifest)
	if strings.Contains(string(raw), canary) {
		t.Fatal("manifest leaked a value")
	}
	m, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}

	ticks := []time.Time{time.Unix(0, 0), time.Unix(2, 0)}
	now := func() time.Time { t0 := ticks[0]; ticks = append(ticks[1:], ticks[0]); return t0 }
	rep, err := Verify(context.Background(), m, key, st, now)
	if err != nil || rep.OK != len(plan.Items) || len(rep.Failed) != 0 || len(rep.Missing) != 0 || rep.Duration != "2s" {
		t.Fatalf("clean verify: %+v %v", rep, err)
	}

	st.vals["pay/stripe"] = []byte("changed")
	delete(st.vals, "mac/one")
	rep, err = Verify(context.Background(), m, key, st, nil)
	if err != nil || rep.OK != len(plan.Items)-2 || len(rep.Failed) != 1 || rep.Failed[0] != "pay/stripe" || len(rep.Missing) != 1 || rep.Missing[0] != "mac/one" {
		t.Fatalf("changed verify: %+v %v", rep, err)
	}

	wrongKey, _ := m.KDF.Key([]byte("another passphrase"))
	rep, _ = Verify(context.Background(), m, wrongKey, st, nil)
	if rep.OK != 0 {
		t.Fatal("a wrong passphrase verified items")
	}

	st.getErr = errors.New("locked")
	if _, err := Verify(context.Background(), m, key, st, nil); err == nil {
		t.Fatal("backend failure not reported")
	}
}

func TestManifestValidation(t *testing.T) {
	kdf := fastKDF(t)
	if _, err := kdf.Key(nil); err == nil {
		t.Fatal("empty passphrase accepted")
	}
	weak := kdf
	weak.MemoryKiB = 1024
	if _, err := weak.Key([]byte("p")); err == nil {
		t.Fatal("weak parameters accepted")
	}
	badSalt := kdf
	badSalt.Salt = "AAAA"
	if _, err := badSalt.Key([]byte("p")); err == nil {
		t.Fatal("short salt accepted")
	}
	for name, doc := range map[string]string{
		"json":    "{",
		"version": `{"version":2}`,
		"kdf":     `{"version":1,"kdf":{"alg":"md5"},"items":[]}`,
		"unknown": `{"version":1,"x":1}`,
	} {
		if _, err := ParseManifest([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnvDefaultsAndExpand(t *testing.T) {
	e := Env{Home: "/h"}.withDefaults()
	if e.ReadFile == nil || e.Glob == nil || e.expand("~/x") != filepath.Join("/h", "x") || e.expand("/a") != "/a" || e.expand("~") != "/h" {
		t.Fatal("env defaults")
	}
}
