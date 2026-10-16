package bws

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

const (
	project = "11111111-2222-3333-4444-555555555555"
	other   = "99999999-2222-3333-4444-555555555555"
	sec1    = "aaaaaaaa-0000-0000-0000-000000000001"
	sec2    = "aaaaaaaa-0000-0000-0000-000000000002"
)

// token is built at run time so the file carries no credential-shaped literal.
var token = strings.Join([]string{"0", "machine", "token"}, ".")

type call struct {
	env  []string
	name string
	args []string
}

type fakeRunner struct {
	calls []call
	reply func(args []string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{env: env, name: name, args: args})
	return f.reply(args)
}

const list = `[
 {"id":"` + sec1 + `","projectId":"` + project + `","key":"stripe/api_key","value":"sk-one"},
 {"id":"` + sec2 + `","projectId":"` + project + `","key":"db/password","value":"pw-two"}
]`

func open(t *testing.T, reply func([]string) ([]byte, error)) (*Backend, *fakeRunner) {
	t.Helper()
	r := &fakeRunner{reply: reply}
	b, err := Open(Options{AccessToken: token, ProjectID: project, Runner: r, Env: func(k string) string {
		if k == "PATH" {
			return "/usr/bin"
		}
		return "must-not-leak"
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, r
}

func listing(args []string) ([]byte, error) {
	if len(args) >= 2 && args[0] == "secret" && args[1] == "list" {
		return []byte(list), nil
	}
	return nil, errors.New("unexpected " + strings.Join(args, " "))
}

func TestOpenValidation(t *testing.T) {
	for name, o := range map[string]Options{
		"no token":    {ProjectID: project},
		"bad project": {AccessToken: token, ProjectID: "not-a-uuid"},
		"http server": {AccessToken: token, ProjectID: project, ServerURL: "http://vault.example"},
	} {
		if _, err := Open(o); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	b, err := Open(Options{AccessToken: token, ProjectID: project})
	if err != nil || b.Name() != "bws" || b.ID() != "bws:"+project || b.opts.Bin != "bws" {
		t.Fatalf("defaults = %+v, %v", b, err)
	}
	if !slices.Contains(b.Capabilities(), backend.CapNetworkedFetch) {
		t.Fatal("bws reaches the network")
	}
}

func TestGetByKey(t *testing.T) {
	b, r := open(t, listing)
	v, m, err := b.Get(context.Background(), "db/password")
	if err != nil || string(v) != "pw-two" || m.Backend != "bws" || m.Path != "db/password" {
		t.Fatalf("Get = %q, %+v, %v", v, m, err)
	}
	if _, _, err := b.Get(context.Background(), "missing"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if len(r.calls) != 2 || r.calls[0].name != "bws" {
		t.Fatalf("calls = %+v", r.calls)
	}
}

func TestGetAmbiguousKeyIsRefused(t *testing.T) {
	b, _ := open(t, func([]string) ([]byte, error) {
		return []byte(`[{"id":"` + sec1 + `","key":"dup","value":"a"},{"id":"` + sec2 + `","key":"dup","value":"b"}]`), nil
	})
	if _, _, err := b.Get(context.Background(), "dup"); err == nil || !strings.Contains(err.Error(), "UUID") {
		t.Fatalf("ambiguous key = %v", err)
	}
}

func TestGetByUUIDStaysInsideTheProject(t *testing.T) {
	b, r := open(t, func(args []string) ([]byte, error) {
		switch args[2] {
		case sec1:
			return []byte(`{"id":"` + sec1 + `","projectId":"` + project + `","key":"k","value":"v1"}`), nil
		case sec2:
			return []byte(`{"id":"` + sec2 + `","projectId":"` + other + `","key":"k","value":"v2"}`), nil
		}
		return nil, errors.New("404")
	})
	if v, _, err := b.Get(context.Background(), sec1); err != nil || string(v) != "v1" {
		t.Fatalf("in project = %q, %v", v, err)
	}
	if _, _, err := b.Get(context.Background(), sec2); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("other project = %v", err)
	}
	if _, _, err := b.Get(context.Background(), "bbbbbbbb-0000-0000-0000-000000000009"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("unknown secret = %v", err)
	}
	if got := r.calls[0].args; got[0] != "secret" || got[1] != "get" || got[2] != sec1 {
		t.Fatalf("args = %v", got)
	}
}

func TestMalformedReplies(t *testing.T) {
	b, _ := open(t, func([]string) ([]byte, error) { return []byte("not json"), nil })
	if _, _, err := b.Get(context.Background(), "k"); err == nil {
		t.Fatal("a malformed list was accepted")
	}
	if _, err := b.List(context.Background(), ""); err == nil {
		t.Fatal("a malformed list was accepted")
	}
	if _, _, err := b.Get(context.Background(), sec1); errors.Is(err, backend.ErrNotFound) || err == nil {
		t.Fatalf("a malformed secret = %v", err)
	}
	failing, _ := open(t, func([]string) ([]byte, error) { return nil, errors.New("exit 1") })
	if _, err := failing.List(context.Background(), ""); err == nil {
		t.Fatal("a CLI failure was ignored")
	}
}

func TestList(t *testing.T) {
	b, _ := open(t, listing)
	got, err := b.List(context.Background(), "db/")
	if err != nil || len(got) != 1 || got[0].Path != "db/password" || !got[0].Exists {
		t.Fatalf("List = %+v, %v", got, err)
	}
	all, _ := b.List(context.Background(), "")
	if len(all) != 2 {
		t.Fatalf("List all = %d", len(all))
	}
}

func TestWritesAreRefused(t *testing.T) {
	b, r := open(t, listing)
	ctx := context.Background()
	for _, err := range []error{
		b.Set(ctx, "k", []byte("v"), backend.Meta{}),
		b.Delete(ctx, "k"),
		b.SetMeta(ctx, "k", vmeta.Meta{}),
		b.SetVersioned(ctx, "k", 1, nil),
		b.DeleteVersioned(ctx, "k", 1),
	} {
		if !errors.Is(err, backend.ErrNotSupported) {
			t.Errorf("a write returned %v", err)
		}
	}
	if _, err := b.GetMeta(ctx, "k"); !errors.Is(err, backend.ErrNotSupported) {
		t.Error("GetMeta is supported")
	}
	if _, err := b.ListMeta(ctx, ""); !errors.Is(err, backend.ErrNotSupported) {
		t.Error("ListMeta is supported")
	}
	if _, err := b.GetVersioned(ctx, "k", 1); !errors.Is(err, backend.ErrNotSupported) {
		t.Error("GetVersioned is supported")
	}
	if len(r.calls) != 0 {
		t.Fatalf("a refused write ran the CLI: %+v", r.calls)
	}
}

func TestTheTokenStaysOutOfArgvAndTheCallerEnvironment(t *testing.T) {
	b, r := open(t, listing)
	if _, err := b.List(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	c := r.calls[0]
	for _, a := range c.args {
		if strings.Contains(a, token) {
			t.Fatalf("the token is in argv: %v", c.args)
		}
	}
	if !slices.Contains(c.env, "BWS_ACCESS_TOKEN="+token) {
		t.Fatalf("env = %v", c.env)
	}
	for _, e := range c.env {
		if strings.Contains(e, "must-not-leak") {
			t.Fatalf("the caller's environment leaked: %s", e)
		}
	}
	var home string
	for _, e := range c.env {
		if h, ok := strings.CutPrefix(e, "HOME="); ok {
			home = h
		}
	}
	if home == "" || home == os.Getenv("HOME") {
		t.Fatalf("the CLI runs in the user's home: %q", home)
	}
	if info, err := os.Stat(home); err != nil || !info.IsDir() {
		t.Fatalf("private home: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("the private home outlived the backend: %v", err)
	}
	if _, err := b.List(context.Background(), ""); err == nil {
		t.Fatal("a closed backend ran the CLI")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func TestServerURLIsPassedAsAFlag(t *testing.T) {
	r := &fakeRunner{reply: listing}
	b, err := Open(Options{AccessToken: token, ProjectID: project, ServerURL: "https://bw.example.org", Bin: "/opt/bws", Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close() //nolint:errcheck
	if _, err := b.List(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(r.calls[0].args, " ")
	if r.calls[0].name != "/opt/bws" || !strings.Contains(args, "--server-url https://bw.example.org") || !strings.Contains(args, "--output json") {
		t.Fatalf("call = %+v", r.calls[0])
	}
}

func TestExecRunnerIsolatesTheEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake CLI is a shell script")
	}
	dir := t.TempDir()
	dump := filepath.Join(dir, "env.txt")
	bin := filepath.Join(dir, "bws")
	script := "#!/bin/sh\nenv > '" + dump + "'\nif [ \"$1\" = fail ]; then echo 'boom' >&2; exit 3; fi\necho '[]'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // G306: a test script
		t.Fatal(err)
	}
	t.Setenv("KEYLATCH_TEST_LEAK", "leaked")
	b, err := Open(Options{AccessToken: token, ProjectID: project, Bin: bin, Env: func(k string) string {
		if k == "PATH" {
			return "/usr/bin:/bin"
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close() //nolint:errcheck
	if _, err := b.List(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "KEYLATCH_TEST_LEAK") || !strings.Contains(string(raw), "BWS_ACCESS_TOKEN="+token) {
		t.Fatalf("child environment:\n%s", raw)
	}
	_, err = ExecRunner{}.Run(context.Background(), []string{"PATH=/usr/bin:/bin"}, bin, "fail")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("a failing CLI = %v", err)
	}
}

func TestFactory(t *testing.T) {
	f, ok := backend.Default.Get("bws")
	if !ok {
		t.Fatal("bws is not registered")
	}
	b, err := f(context.Background(), backend.BackendConfig{Name: "bws", Settings: map[string]interface{}{
		"access_token": token, "project_id": project, "server_url": "https://bw.example.org", "env": func(string) string { return "" },
	}})
	if err != nil || b.Name() != "bws" {
		t.Fatalf("factory = %v, %v", b, err)
	}
	_ = b.Close()
	for name, s := range map[string]map[string]interface{}{
		"unknown key": {"access_token": token, "project_id": project, "surprise": "x"},
		"no token":    {"project_id": project},
	} {
		if _, err := f(context.Background(), backend.BackendConfig{Name: "bws", Settings: s}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
