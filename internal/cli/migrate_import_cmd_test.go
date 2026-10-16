package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/migrate"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"github.com/keylatch/keylatch/internal/testutil"
)

var importCanary = "canary" + "-import-" + "41d7"

type fakeMigrateStore struct {
	mu   sync.Mutex
	vals map[string][]byte
	puts int
}

func (s *fakeMigrateStore) Get(_ context.Context, p string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vals[p]
	if !ok {
		return nil, migrate.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (s *fakeMigrateStore) Put(_ context.Context, p string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts++
	s.vals[p] = append([]byte(nil), v...)
	return nil
}

type migrateFixture struct {
	dir     string
	store   *fakeMigrateStore
	plan    string
	mapFile string
}

func newMigrateFixture(t *testing.T) *migrateFixture {
	t.Helper()
	testutil.SetupHermeticConfig(t)
	testutil.ClearLLMSessionEnv(t)
	dir := t.TempDir()
	f := &migrateFixture{dir: dir, store: &fakeMigrateStore{vals: map[string][]byte{}}, plan: filepath.Join(dir, "plan.json")}
	if err := os.WriteFile(filepath.Join(dir, "app.env"), []byte("TOKEN_A="+importCanary+"\nTOKEN_B="+importCanary+"-b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mapFile := filepath.Join(dir, "map.yaml")
	f.mapFile = mapFile
	if err := os.WriteFile(mapFile, []byte("version: 1\nsources:\n  - {type: env-file, namespace: apps, glob: \""+filepath.ToSlash(filepath.Join(dir, "*.env"))+"\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prevEnv, prevOpen := migrateEnv, openMigrateStore
	migrateEnv = func() migrate.Env { return migrate.Env{Home: dir} }
	openMigrateStore = func(context.Context, string, config.Config, llmcontext.Lookup) (migrate.Store, error) {
		return f.store, nil
	}
	t.Cleanup(func() { migrateEnv, openMigrateStore = prevEnv, prevOpen })
	out, err := runMigrateCLI(t, "", "inventory", "--map", mapFile, "--out", f.plan)
	if err != nil {
		t.Fatalf("inventory: %v\n%s", err, out)
	}
	return f
}

func runMigrateCLI(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(append([]string{"migrate"}, args...))
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func runDrill(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(append([]string{"drill"}, args...))
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestInventoryHasNoValues(t *testing.T) {
	f := newMigrateFixture(t)
	data, err := os.ReadFile(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), importCanary) {
		t.Fatalf("plan holds a value: %s", data)
	}
	if !strings.Contains(string(data), "apps/token_a") {
		t.Fatalf("plan lacks the item: %s", data)
	}
	out, err := runMigrateCLI(t, "", "inventory", "--map", filepath.Join(f.dir, "missing.yaml"))
	if err == nil || strings.Contains(out, importCanary) {
		t.Fatalf("missing map: %v", err)
	}
}

func TestImportNeedsPresence(t *testing.T) {
	f := newMigrateFixture(t)
	presencetest.Decline(t)
	_, err := runMigrateCLI(t, "", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw")
	assertSecurityBlock(t, err)
	if f.store.puts != 0 {
		t.Fatal("a declined import wrote")
	}
	presencetest.NoTerminal(t)
	_, err = runMigrateCLI(t, "", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "op")
	assertSecurityBlock(t, err)
}

func TestImportIdempotent(t *testing.T) {
	f := newMigrateFixture(t)
	presencetest.Approve(t)
	out, err := runMigrateCLI(t, "", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw")
	if err != nil || strings.Contains(out, importCanary) {
		t.Fatalf("import: %v\n%s", err, out)
	}
	puts := f.store.puts
	if puts != 2 {
		t.Fatalf("puts = %d, want 2", puts)
	}
	out, err = runMigrateCLI(t, "", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw")
	if err != nil || f.store.puts != puts || !strings.Contains(out, `"unchanged": 2`) {
		t.Fatalf("second import: %v puts %d\n%s", err, f.store.puts, out)
	}
}

func TestImportRefusesAPlanThatLeavesItsMap(t *testing.T) {
	f := newMigrateFixture(t)
	presencetest.Approve(t)
	data, err := os.ReadFile(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	var plan migrate.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) == 0 || !strings.HasPrefix(plan.Items[0].Ref, "env:") {
		t.Fatalf("the plan names no env file: %s", data)
	}
	plan.Items[0].Ref = "env:/etc/hostname#TOKEN_A"
	forged, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(f.dir, "forged.json")
	if err := os.WriteFile(bad, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runMigrateCLI(t, "", "import", "--plan", bad, "--map", f.mapFile, "--to", "bw"); err == nil || f.store.puts != 0 {
		t.Fatalf("a forged plan imported: %v (%d puts)", err, f.store.puts)
	}
	if _, err := runMigrateCLI(t, "", "import", "--plan", f.plan, "--to", "bw"); err == nil {
		t.Fatal("import without a map")
	}
}

func TestImportPresenceNamesSourcesAndPaths(t *testing.T) {
	f := newMigrateFixture(t)
	seen := presencetest.Record(t)
	if _, err := runMigrateCLI(t, "", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw"); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 {
		t.Fatalf("presence asked %d times", len(*seen))
	}
	for _, want := range []string{"app.env#TOKEN_A", "apps/token_a", "apps/token_b", "env-file"} {
		if !strings.Contains((*seen)[0], want) {
			t.Errorf("the approval %q lacks %q", (*seen)[0], want)
		}
	}
}

func TestDescribePlanCapsTheList(t *testing.T) {
	var items []migrate.PlanItem
	for i := 0; i < 30; i++ {
		items = append(items, migrate.PlanItem{Ref: "env:/a#K", Source: "env-file", Path: "apps/k"})
	}
	if got := describePlan(migrate.Plan{Items: items}); !strings.Contains(got, "and 5 more") {
		t.Fatalf("describePlan = %q", got)
	}
}

func TestDryRunRunsNoLookupToolsForAnAgent(t *testing.T) {
	f := newMigrateFixture(t)
	t.Setenv("CLAUDECODE", "1")
	// File sources are still compared.
	if _, err := runMigrateCLI(t, "", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw", "--dry-run"); err != nil {
		t.Fatalf("file-only dry run for an agent: %v", err)
	}
	m := filepath.Join(f.dir, "tools.yaml")
	if err := os.WriteFile(m, []byte("version: 1\nsources:\n  - {type: gh, namespace: github}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(f.dir, "tools.json")
	body := `{"version":1,"items":[{"name":"gh-github.com","source":"gh","ref":"gh:github.com","namespace":"github","collection":"github","path":"github/gh-github.com"}]}`
	if err := os.WriteFile(plan, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	prev := migrateEnv
	migrateEnv = func() migrate.Env {
		return migrate.Env{Home: f.dir, Run: func(context.Context, string, ...string) ([]byte, error) { ran = true; return []byte("x"), nil }}
	}
	defer func() { migrateEnv = prev }()
	if _, err := runMigrateCLI(t, "", "import", "--plan", plan, "--map", m, "--to", "bw", "--dry-run"); err == nil || ran {
		t.Fatalf("an agent's dry run ran a lookup tool: err=%v ran=%v", err, ran)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	f := newMigrateFixture(t)
	presencetest.Decline(t)
	out, err := runMigrateCLI(t, "", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw", "--dry-run")
	if err != nil || f.store.puts != 0 || !strings.Contains(out, "would-write") {
		t.Fatalf("dry run: %v puts %d\n%s", err, f.store.puts, out)
	}
}

func TestImportRejectsBadInput(t *testing.T) {
	f := newMigrateFixture(t)
	presencetest.Approve(t)
	for _, args := range [][]string{
		{"import", "--plan", f.plan, "--map", f.mapFile, "--to", "keychain"},
		{"import", "--plan", filepath.Join(f.dir, "nope.json"), "--map", f.mapFile, "--to", "bw"},
		{"verify", "--manifest", filepath.Join(f.dir, "nope.json")},
	} {
		if _, err := runMigrateCLI(t, "", args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	bad := filepath.Join(f.dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"version":9}`), 0o600)
	if _, err := runMigrateCLI(t, "", "import", "--plan", bad, "--map", f.mapFile, "--to", "bw"); err == nil {
		t.Error("bad plan accepted")
	}
	if _, err := runMigrateCLI(t, "", "verify", "--manifest", bad); err == nil {
		t.Error("bad manifest accepted")
	}
	if _, err := runMigrateCLI(t, "", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw", "--manifest-out", filepath.Join(f.dir, "m.json"), "--passphrase-stdin"); err == nil {
		t.Error("empty passphrase accepted")
	}
}

func TestVerifyDetectsChange(t *testing.T) {
	f := newMigrateFixture(t)
	presencetest.Approve(t)
	manifest := filepath.Join(f.dir, "manifest.json")
	if out, err := runMigrateCLI(t, "recovery phrase\n", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw", "--manifest-out", manifest, "--passphrase-stdin"); err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile(manifest)
	if strings.Contains(string(raw), importCanary) {
		t.Fatal("manifest holds a value")
	}
	out, err := runMigrateCLI(t, "recovery phrase\n", "verify", "--manifest", manifest, "--passphrase-stdin")
	if err != nil || !strings.Contains(out, `"ok": 2`) {
		t.Fatalf("clean verify: %v\n%s", err, out)
	}
	f.store.vals["apps/token_a"] = []byte("changed")
	out, err = runMigrateCLI(t, "recovery phrase\n", "verify", "--manifest", manifest, "--passphrase-stdin")
	if err == nil || !strings.Contains(out, "apps/token_a") || strings.Contains(out, "changed") {
		t.Fatalf("changed verify: %v\n%s", err, out)
	}
	if _, err := runMigrateCLI(t, "wrong phrase\n", "verify", "--manifest", manifest, "--passphrase-stdin"); err == nil {
		t.Fatal("a wrong passphrase verified")
	}
	if _, err := runMigrateCLI(t, "recovery phrase\n", "verify", "--manifest", manifest, "--passphrase-stdin", "--to", "broker"); err == nil {
		t.Fatal("broker verification accepted")
	}
}

func TestDrillRestoreReport(t *testing.T) {
	f := newMigrateFixture(t)
	presencetest.Approve(t)
	manifest := filepath.Join(f.dir, "manifest.json")
	if _, err := runMigrateCLI(t, "p\n", "import", "--plan", f.plan, "--map", f.mapFile, "--to", "bw", "--manifest-out", manifest, "--passphrase-stdin"); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(f.dir, "report.json")
	if _, err := runDrill(t, "p\n", "restore", "--manifest", manifest, "--report", report, "--passphrase-stdin"); err != nil {
		t.Fatalf("clean drill: %v", err)
	}
	var rep migrate.Report
	data, _ := os.ReadFile(report)
	if err := json.Unmarshal(data, &rep); err != nil || rep.OK != 2 {
		t.Fatalf("report %s: %v", data, err)
	}
	delete(f.store.vals, "apps/token_b")
	out, err := runDrill(t, "p\n", "restore", "--manifest", manifest, "--report", "-", "--passphrase-stdin")
	if err == nil || !strings.Contains(out, `"missing": [`) || !strings.Contains(out, "apps/token_b") {
		t.Fatalf("drill with a missing item: %v\n%s", err, out)
	}
}

type importBroker struct {
	listed  []brokerapi.Entry
	imports []brokerapi.Request
	tamper  bool
	failing bool
}

func (b *importBroker) Call(req brokerapi.Request) (brokerapi.Response, error) {
	switch req.Op {
	case brokerapi.OpSecretList:
		return brokerapi.Response{OK: true, Entries: b.listed}, nil
	case brokerapi.OpPresenceBegin:
		d := req.Target.Digest()
		return brokerapi.Response{OK: true, Proof: &brokerapi.Proof{ID: strings.Repeat("ab", 32), Digest: d, Method: "test"}}, nil
	case brokerapi.OpMigrateImport:
		if b.failing {
			return brokerapi.Response{}, errors.New("socket closed")
		}
		b.imports = append(b.imports, req)
		macs := map[string]string{}
		for _, it := range req.Items {
			macs[it.Path] = brokerd.KeyedHash(req.Nonce, it.Path, it.Value)
			if b.tamper {
				macs[it.Path] = "00"
			}
		}
		return brokerapi.Response{OK: true, MACs: macs}, nil
	}
	return brokerapi.Response{}, errors.New("unexpected op")
}

func TestBrokerImportStoreBatchesOneRequest(t *testing.T) {
	fb := &importBroker{listed: []brokerapi.Entry{{Path: "apps/token_a"}}}
	prevInstalled, prevDial := brokerInstalled, dialBroker
	brokerInstalled = func(llmcontext.Lookup) bool { return true }
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) { return fb, nil }
	t.Cleanup(func() { brokerInstalled, dialBroker = prevInstalled, prevDial })

	store, err := openBrokerImportStore(llmcontext.DefaultLookup)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.Get(ctx, "apps/token_a"); !errors.Is(err, migrate.ErrUnreadable) {
		t.Fatalf("existing item: %v", err)
	}
	if _, err := store.Get(ctx, "apps/new"); !errors.Is(err, migrate.ErrNotFound) {
		t.Fatalf("new item: %v", err)
	}
	res := migrate.Import(ctx, migrate.Plan{Version: 1, Items: []migrate.PlanItem{
		{Name: "a", Source: "gh", Ref: "env:" + writeTempEnv(t, "A=1\nB=2\n") + "#A", Path: "apps/token_a"},
		{Name: "b", Source: "gh", Ref: "env:" + writeTempEnv(t, "A=1\nB=2\n") + "#B", Path: "apps/b"},
	}}, migrate.Env{}, store, migrate.ImportOptions{})
	if res.Written != 1 || res.Unchanged != 1 || len(fb.imports) != 1 || len(fb.imports[0].Items) != 1 {
		t.Fatalf("import: %+v requests %d", res, len(fb.imports))
	}

	fb.tamper = true
	store, _ = openBrokerImportStore(llmcontext.DefaultLookup)
	res = migrate.Import(ctx, migrate.Plan{Version: 1, Items: []migrate.PlanItem{{Name: "b", Source: "gh", Ref: "env:" + writeTempEnv(t, "B=2\n") + "#B", Path: "apps/c"}}}, migrate.Env{}, store, migrate.ImportOptions{})
	if res.Failed != 1 {
		t.Fatalf("a mismatching broker hash was accepted: %+v", res)
	}
	fb.tamper, fb.failing = false, true
	store, _ = openBrokerImportStore(llmcontext.DefaultLookup)
	res = migrate.Import(ctx, migrate.Plan{Version: 1, Items: []migrate.PlanItem{{Name: "b", Source: "gh", Ref: "env:" + writeTempEnv(t, "B=2\n") + "#B", Path: "apps/d"}}}, migrate.Env{}, store, migrate.ImportOptions{})
	if res.Failed != 1 {
		t.Fatalf("a failed broker request was accepted: %+v", res)
	}
}

func writeTempEnv(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBrokerImportStoreNeedsBroker(t *testing.T) {
	prev := brokerInstalled
	brokerInstalled = func(llmcontext.Lookup) bool { return false }
	t.Cleanup(func() { brokerInstalled = prev })
	if _, err := openBrokerImportStore(llmcontext.DefaultLookup); err == nil {
		t.Fatal("no broker accepted")
	}
}
