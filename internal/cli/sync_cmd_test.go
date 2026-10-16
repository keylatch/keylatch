package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/llmcontext"
	keysync "github.com/keylatch/keylatch/internal/sync"
	"github.com/keylatch/keylatch/internal/sync/targets"
	"github.com/keylatch/keylatch/internal/testutil"
)

var cliSyncCanary = "canary" + "-cli-sync-" + "27ab"

const cliSyncManifest = `version: 1
targets:
  web:   {type: vercel, project: prj_1, credential: vercel-deploy}
  local: {type: env-file, path: .env.local}
vars:
  - name: DATABASE_URL
    from: {connection: app-db, field: url}
    to: {web: [production], local: [file]}
`

// syncBroker is the daemon as the CLI sees it: it records the requests and
// answers from a script. It plays the daemon's part for descriptors too.
type syncBroker struct {
	requests []brokerapi.Request
	answer   func(brokerapi.Request) brokerapi.Response
	merged   string
	refuse   bool
	// idle makes the fake daemon leave the output files empty, as the real one
	// does for a target that needs no change.
	idle bool
}

func (b *syncBroker) Call(req brokerapi.Request) (brokerapi.Response, error) {
	b.requests = append(b.requests, req)
	if req.Op == brokerapi.OpPresenceBegin {
		if b.refuse {
			return brokerapi.Response{Code: brokerapi.CodePresenceRequired, Error: "not approved"}, nil
		}
		return brokerapi.Response{OK: true, Proof: &brokerapi.Proof{ID: strings.Repeat("cd", 32), Digest: req.Target.Digest(), Method: "test"}}, nil
	}
	return b.answer(req), nil
}

func (b *syncBroker) CallWithFiles(req brokerapi.Request, files []*os.File) (brokerapi.Response, error) {
	b.requests = append(b.requests, req)
	if b.idle {
		return b.answer(req), nil
	}
	existing, _ := io.ReadAll(files[0])
	b.merged = string(existing) + "DATABASE_URL=" + cliSyncCanary + "\n"
	if _, err := files[1].WriteString(b.merged); err != nil {
		return brokerapi.Response{}, err
	}
	return b.answer(req), nil
}

type syncFixture struct {
	dir    string
	broker *syncBroker
	out    *bytes.Buffer
}

func newSyncFixture(t *testing.T, installed bool) *syncFixture {
	t.Helper()
	testutil.SetupHermeticConfig(t)
	testutil.ClearLLMSessionEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keysync.DefaultFile), []byte(cliSyncManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env.local"), []byte("# mine\nKEEP="+cliSyncCanary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &syncFixture{dir: dir, broker: &syncBroker{}, out: &bytes.Buffer{}}
	prevGit, prevInst, prevDial, prevHook := syncGit, brokerInstalled, dialBroker, syncBuildHook
	syncGit = func(_ string, args ...string) (string, int) {
		switch args[0] {
		case "rev-parse":
			return dir, 0
		case "check-ignore":
			return "", 0
		case "ls-files":
			return "", 1
		}
		return "", -1
	}
	brokerInstalled = func(llmcontext.Lookup) bool { return installed }
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) { return f.broker, nil }
	t.Cleanup(func() { syncGit, brokerInstalled, dialBroker, syncBuildHook = prevGit, prevInst, prevDial, prevHook })
	return f
}

func (f *syncFixture) run(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewRootCommand()
	cmd.SetOut(f.out)
	cmd.SetErr(f.out)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs(append([]string{"sync", "--file", filepath.Join(f.dir, keysync.DefaultFile)}, args...))
	return cmd.ExecuteContext(context.Background())
}

func exitOf(err error) int {
	var rep *reportedError
	if errors.As(err, &rep) {
		return rep.code
	}
	return -1
}

func TestSyncCheckReportsTheKeyPath(t *testing.T) {
	f := newSyncFixture(t, false)
	if err := f.run(t, "check"); err != nil || !strings.Contains(f.out.String(), "ok: 2 target(s), 1 variable(s)") {
		t.Fatalf("check = %v\n%s", err, f.out)
	}
	bad := strings.Replace(cliSyncManifest, "web: [production]", "web: [staging]", 1)
	if err := os.WriteFile(filepath.Join(f.dir, keysync.DefaultFile), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	err := f.run(t, "check")
	if err == nil || !strings.Contains(err.Error(), "vars[0].to.web[0]") {
		t.Fatalf("check = %v", err)
	}
	// An env file git does not ignore is refused.
	syncGit = func(_ string, args ...string) (string, int) {
		if args[0] == "check-ignore" {
			return "", 1
		}
		return dirOrNil(f.dir, args[0])
	}
	_ = os.WriteFile(filepath.Join(f.dir, keysync.DefaultFile), []byte(cliSyncManifest), 0o600)
	if err := f.run(t, "check"); err == nil || !strings.Contains(err.Error(), "not git-ignored") {
		t.Fatalf("an unignored env file: %v", err)
	}
}

func dirOrNil(dir, verb string) (string, int) {
	if verb == "rev-parse" {
		return dir, 0
	}
	return "", 1
}

func TestSyncDriftExitCodes(t *testing.T) {
	f := newSyncFixture(t, true)
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{OK: true, Sync: &brokerapi.SyncResult{Changes: []keysync.Change{
			{Target: "web", Environment: "production", Name: "DATABASE_URL", Kind: keysync.KindAdd, Reason: "missing"},
		}}}
	}
	err := f.run(t, "drift")
	if exitOf(err) != 1 || !strings.Contains(f.out.String(), "add") || !strings.Contains(f.out.String(), "DATABASE_URL") {
		t.Fatalf("drift = %v\n%s", err, f.out)
	}
	f.out.Reset()
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{OK: true, Sync: &brokerapi.SyncResult{Changes: []keysync.Change{
			{Target: "web", Environment: "production", Name: "DATABASE_URL", Kind: keysync.KindUnchanged},
		}}}
	}
	if err := f.run(t, "drift", "--json"); err != nil || !strings.Contains(f.out.String(), `"drift": false`) {
		t.Fatalf("clean drift = %v\n%s", err, f.out)
	}
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{Code: brokerapi.CodeRefused, Error: "policy is tampered"}
	}
	if err := f.run(t, "drift"); err == nil || exitOf(err) == 1 {
		t.Fatalf("a daemon refusal must not look like drift: %v", err)
	}
}

func TestSyncDriftNeedsNoBackendSession(t *testing.T) {
	f := newSyncFixture(t, false)
	remote := &cliFakeRemote{}
	syncBuildHook = func(o *targets.BuildOptions) {
		o.Override = func(name string, _ keysync.Target, _ targets.Token) (keysync.TargetClient, bool) {
			if name == "web" {
				return remote, true
			}
			return nil, false
		}
	}
	// The manifest names a variable the target lacks, and the credential is never read.
	err := f.run(t, "drift", "--json")
	if exitOf(err) != 1 {
		t.Fatalf("missing names must exit 1: %v\n%s", err, f.out)
	}
	var doc struct {
		Drift   bool           `json:"drift"`
		Counts  map[string]int `json:"counts"`
		Changes []keysync.Change
	}
	if json.Unmarshal(f.out.Bytes(), &doc) != nil || !doc.Drift || doc.Counts["add"] != 2 {
		t.Fatalf("output: %s", f.out)
	}
	// An extra name is drift too.
	remote.entries = []keysync.Remote{{Name: "STRAY", Environments: []string{"production"}}, {Name: "DATABASE_URL", Environments: []string{"production"}}}
	f.out.Reset()
	if err := f.run(t, "drift"); exitOf(err) != 1 || !strings.Contains(f.out.String(), "STRAY") {
		t.Fatalf("extra = %v\n%s", err, f.out)
	}
	// apply and rotate never run without the broker.
	for _, args := range [][]string{{"apply"}, {"rotate", "DATABASE_URL"}} {
		if err := f.run(t, args...); err == nil || !strings.Contains(err.Error(), "system broker") {
			t.Fatalf("%v without a broker = %v", args, err)
		}
	}
	// A session that belongs to an agent cannot use the local fallback.
	t.Setenv("CLAUDECODE", "1")
	if err := f.run(t, "drift"); err == nil {
		t.Fatal("an agent session used the local fallback")
	}
}

type cliFakeRemote struct{ entries []keysync.Remote }

func (*cliFakeRemote) ID() string { return "vercel:prj_1" }
func (c *cliFakeRemote) List(context.Context) ([]keysync.Remote, error) {
	return c.entries, nil
}
func (*cliFakeRemote) Write(context.Context, string, []byte, []string, bool) error { return nil }
func (*cliFakeRemote) Delete(context.Context, keysync.Remote) error                { return nil }
func (*cliFakeRemote) Readback(context.Context, keysync.Remote) ([]byte, bool, error) {
	return nil, false, nil
}

func TestSyncOutputCanary(t *testing.T) {
	f := newSyncFixture(t, true)
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{OK: true, Sync: &brokerapi.SyncResult{
			Changes: []keysync.Change{{Target: "local", Environment: "file", Name: "DATABASE_URL", Kind: keysync.KindUpdate, Reason: keysync.ReasonSource}},
			Entries: []keysync.Entry{{Target: "local", Environment: "file", Name: "DATABASE_URL", Outcome: keysync.OutcomeWritten}},
		}}
	}
	for _, args := range [][]string{{"diff"}, {"diff", "--json", "--all", "--prune"}, {"drift", "--json"}, {"check"}} {
		f.out.Reset()
		_ = f.run(t, args...)
		if strings.Contains(f.out.String(), cliSyncCanary) {
			t.Fatalf("sync %v printed a value:\n%s", args, f.out)
		}
	}
	// No request carries a value: only names read from the env file.
	for _, r := range f.broker.requests {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), cliSyncCanary) {
			t.Fatalf("a request carries a value: %s", b)
		}
		if r.Sync != nil && r.Sync.EnvKeys["local"][0] != "KEEP" {
			t.Fatalf("env keys = %v", r.Sync.EnvKeys)
		}
	}
}

func TestSyncApplyNeedsPresence(t *testing.T) {
	f := newSyncFixture(t, true)
	f.broker.refuse = true
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		t.Fatal("apply reached the daemon without a proof")
		return brokerapi.Response{}
	}
	assertSecurityBlock(t, f.run(t, "apply"))
	if matches, _ := filepath.Glob(filepath.Join(f.dir, ".keylatch-sync-*")); len(matches) != 0 {
		t.Fatalf("a refused apply left temp files: %v", matches)
	}
}

func TestSyncEnvFileAtomic0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes and descriptor passing are Unix features")
	}
	f := newSyncFixture(t, true)
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response {
		if len(req.Sync.EnvFiles) != 1 || req.Sync.EnvFiles[0] != "local" {
			t.Errorf("env files = %v", req.Sync.EnvFiles)
		}
		return brokerapi.Response{OK: true, Sync: &brokerapi.SyncResult{Entries: []keysync.Entry{
			{Target: "local", Environment: "file", Name: "DATABASE_URL", Outcome: keysync.OutcomeWritten},
		}}}
	}
	if err := f.run(t, "apply"); err != nil {
		t.Fatalf("apply = %v\n%s", err, f.out)
	}
	got, err := os.ReadFile(filepath.Join(f.dir, ".env.local"))
	if err != nil || string(got) != f.broker.merged {
		t.Fatalf("env file = %q, %v", got, err)
	}
	if !strings.Contains(string(got), "# mine\nKEEP=") {
		t.Fatal("unmanaged lines were lost")
	}
	if info, _ := os.Stat(filepath.Join(f.dir, ".env.local")); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	if matches, _ := filepath.Glob(filepath.Join(f.dir, ".keylatch-sync-*")); len(matches) != 0 {
		t.Fatalf("temp files left: %v", matches)
	}
	if strings.Contains(f.out.String(), cliSyncCanary) {
		t.Fatal("apply printed a value")
	}
	// A failed apply leaves the env file as it was and no temp file behind.
	before, _ := os.ReadFile(filepath.Join(f.dir, ".env.local"))
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{Code: brokerapi.CodeUnavailable, Error: "target refused", Sync: &brokerapi.SyncResult{}}
	}
	if err := f.run(t, "apply"); err == nil {
		t.Fatal("a failed apply reported success")
	}
	if after, _ := os.ReadFile(filepath.Join(f.dir, ".env.local")); !bytes.Equal(before, after) {
		t.Fatal("a failed apply changed the env file")
	}
	if matches, _ := filepath.Glob(filepath.Join(f.dir, ".keylatch-sync-*")); len(matches) != 0 {
		t.Fatalf("temp files left after a failure: %v", matches)
	}
}

func TestSyncApplyIdempotentKeepsTheEnvFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes and descriptor passing are Unix features")
	}
	f := newSyncFixture(t, true)
	f.broker.idle = true
	path := filepath.Join(f.dir, ".env.local")
	before, _ := os.ReadFile(path)
	for name, entries := range map[string][]keysync.Entry{
		"unchanged":        {{Target: "local", Environment: "file", Name: "DATABASE_URL", Outcome: keysync.OutcomeUnchanged}},
		"failed":           {{Target: "local", Environment: "file", Name: "DATABASE_URL", Outcome: keysync.OutcomeFailed, Error: "source missing"}},
		"another target":   {{Target: "web", Environment: "production", Name: "DATABASE_URL", Outcome: keysync.OutcomeWritten}},
		"nothing reported": nil,
	} {
		f.broker.answer = func(brokerapi.Request) brokerapi.Response {
			return brokerapi.Response{OK: true, Sync: &brokerapi.SyncResult{Entries: entries}}
		}
		_ = f.run(t, "apply")
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("%s: env file = %q, %v", name, after, err)
		}
		if matches, _ := filepath.Glob(filepath.Join(f.dir, ".keylatch-sync-*")); len(matches) != 0 {
			t.Fatalf("%s: temp files left: %v", name, matches)
		}
	}
}

func TestSyncRotateAndPruneRequests(t *testing.T) {
	f := newSyncFixture(t, true)
	var seen []brokerapi.Request
	f.broker.answer = func(req brokerapi.Request) brokerapi.Response {
		seen = append(seen, req)
		return brokerapi.Response{OK: true, Sync: &brokerapi.SyncResult{Entries: []keysync.Entry{{Target: "web", Environment: "production", Name: "DATABASE_URL", Outcome: keysync.OutcomeVerified}}}}
	}
	if err := f.run(t, "rotate", "DATABASE_URL", "--target", "web", "--keep-old", "90s", "--no-rollback"); err != nil {
		t.Fatalf("rotate = %v\n%s", err, f.out)
	}
	if len(seen) != 1 {
		t.Fatalf("requests = %d", len(seen))
	}
	s := seen[0].Sync
	if seen[0].Op != brokerapi.OpSyncRotate || s.Name != "DATABASE_URL" || s.Target != "web" || s.KeepOldSeconds != 90 || !s.NoRollback || len(s.EnvFiles) != 0 {
		t.Fatalf("rotate request = %+v", s)
	}
	if err := f.run(t, "rotate", "DATABASE_URL", "--keep-old", "48h"); err == nil {
		t.Fatal("keep-old beyond 24h accepted")
	}
	f.out.Reset()
	if err := f.run(t, "apply", "--prune", "--json"); err == nil {
		// the env file target needs the descriptor path; the fake supports it
		if !strings.Contains(f.out.String(), "entries") {
			t.Fatalf("apply output: %s", f.out)
		}
	}
	if last := seen[len(seen)-1]; !last.Sync.Prune {
		t.Fatal("--prune not sent")
	}
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{OK: true, Sync: &brokerapi.SyncResult{Entries: []keysync.Entry{{Target: "web", Environment: "production", Name: "X", Outcome: keysync.OutcomeFailed, Error: "boom"}}}}
	}
	if err := f.run(t, "apply"); exitOf(err) == 0 || err == nil {
		t.Fatalf("a failed entry must fail the command: %v", err)
	}
}

func TestSyncFilterString(t *testing.T) {
	if got := filterString([]string{"a", "b", "a"}, "a"); len(got) != 2 {
		t.Fatalf("filterString = %v", got)
	}
}

func TestSyncAgentRefusedBeforeBackendRead(t *testing.T) {
	f := newSyncFixture(t, true)
	f.broker.answer = func(brokerapi.Request) brokerapi.Response {
		t.Fatal("an agent session reached the daemon")
		return brokerapi.Response{}
	}
	t.Setenv("CLAUDECODE", "1")
	for _, args := range [][]string{{"apply"}, {"apply", "--prune"}, {"rotate", "DATABASE_URL"}} {
		err := f.run(t, args...)
		assertSecurityBlock(t, err)
		if !strings.Contains(err.Error(), "keylatch sync "+args[0]) {
			t.Fatalf("the refusal must name the command for the human: %v", err)
		}
	}
	if len(f.broker.requests) != 0 {
		t.Fatalf("requests = %d", len(f.broker.requests))
	}
}

func TestSyncGitDefaultAnswersFromGit(t *testing.T) {
	dir := t.TempDir()
	if _, code := syncGit(dir, "init", "-q"); code != 0 {
		t.Skip("git is not available")
	}
	_ = os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".env.local\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "tracked.env"), []byte("A=1\n"), 0o600)
	if _, code := syncGit(dir, "add", "-f", "tracked.env"); code != 0 {
		t.Skip("git add failed in this environment")
	}
	repo := keysync.GitRepo{Root: dir, Git: syncGit}
	if ok, err := repo.Ignored(".env.local"); err != nil || !ok {
		t.Fatalf("ignored = %v %v", ok, err)
	}
	if ok, err := repo.Ignored("other.env"); err != nil || ok {
		t.Fatalf("not ignored = %v %v", ok, err)
	}
	if ok, err := repo.Tracked("tracked.env"); err != nil || !ok {
		t.Fatalf("tracked = %v %v", ok, err)
	}
	if ok, err := repo.Tracked(".env.local"); err != nil || ok {
		t.Fatalf("untracked = %v %v", ok, err)
	}
	if _, code := syncGit(filepath.Join(dir, "missing"), "status"); code == 0 {
		t.Fatal("git in a missing directory succeeded")
	}
}
