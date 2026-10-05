package grant_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/grant"
)

// fakeProgram creates an executable file named name in a fresh directory and
// returns its absolute path.
func fakeProgram(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func findWithGrant(t *testing.T, spec grant.GrantSpec, req grant.FindRequest) bool {
	t.Helper()
	env := tempEnv(t)
	ctx := context.Background()
	spec.Actor, spec.Connection, spec.Capability, spec.TTL = "human-shell", "c", "inject", time.Hour
	if _, err := grant.Create(ctx, spec, env); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, ok := grant.Find(ctx, env("KEYLATCH_GRANTS_PATH"), req)
	return ok
}

func TestFindEnforcesGrantScope(t *testing.T) {
	npm := fakeProgram(t, "npm")
	other := fakeProgram(t, "npm")
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	sibling := filepath.Join(root, "repo-other")
	mkdirs(t, filepath.Join(repo, "pkg", "a"), sibling)

	base := grant.FindRequest{
		Actor:      "human-shell",
		Connection: "c",
		Capability: "inject",
		Command:    []string{npm, "test"},
		CWD:        repo,
	}

	cases := []struct {
		name    string
		command string
		cwd     string
		mutate  func(*grant.FindRequest)
		want    bool
	}{
		{name: "unrestricted grant matches", want: true},
		{name: "exact command matches", command: npm + " test", want: true},
		{name: "other command rejected", command: npm + " test", mutate: func(r *grant.FindRequest) { r.Command = []string{npm, "run", "evil"} }},
		{name: "other program with the same name rejected", command: npm + " test", mutate: func(r *grant.FindRequest) { r.Command = []string{other, "test"} }},
		{name: "no implicit argument extension", command: npm + " test", mutate: func(r *grant.FindRequest) { r.Command = []string{npm, "test", "--", "x"} }},
		{name: "separate trailing wildcard extends", command: npm + " test *", mutate: func(r *grant.FindRequest) { r.Command = []string{npm, "test", "--", "x"} }, want: true},
		{name: "separate trailing wildcard allows no extra arguments", command: npm + " test *", want: true},
		{name: "wildcard does not extend an argument", command: npm + " test *", mutate: func(r *grant.FindRequest) { r.Command = []string{npm, "testevil"} }},
		{name: "arguments are compared one by one", command: npm + " test", mutate: func(r *grant.FindRequest) { r.Command = []string{npm + " test"} }},
		{name: "restricted command needs a command", command: npm + " test", mutate: func(r *grant.FindRequest) { r.Command = nil }},
		{name: "exact cwd matches", cwd: repo, want: true},
		{name: "other cwd rejected", cwd: repo, mutate: func(r *grant.FindRequest) { r.CWD = sibling }},
		{name: "subtree cwd matches subdirectory", cwd: repo + "/*", mutate: func(r *grant.FindRequest) { r.CWD = filepath.Join(repo, "pkg", "a") }, want: true},
		{name: "subtree cwd matches its root", cwd: repo + "/*", want: true},
		{name: "subtree cwd rejects sibling prefix", cwd: repo + "/*", mutate: func(r *grant.FindRequest) { r.CWD = sibling }},
		{name: "subtree cwd rejects parent", cwd: repo + "/*", mutate: func(r *grant.FindRequest) { r.CWD = root }},
		{name: "restricted cwd needs a cwd", cwd: repo, mutate: func(r *grant.FindRequest) { r.CWD = "" }},
		{name: "empty actor does not match restricted grant", mutate: func(r *grant.FindRequest) { r.Actor = "" }},
		{name: "empty connection does not match restricted grant", mutate: func(r *grant.FindRequest) { r.Connection = "" }},
		{name: "empty capability does not match restricted grant", mutate: func(r *grant.FindRequest) { r.Capability = "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			if got := findWithGrant(t, grant.GrantSpec{Command: tc.command, CWD: tc.cwd}, req); got != tc.want {
				t.Fatalf("Find = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCreateRejectsGluedWildcard(t *testing.T) {
	npm := fakeProgram(t, "npm")
	for _, cmd := range []string{npm + " test*", "* test", npm + " * test"} {
		_, err := grant.Create(context.Background(), grant.GrantSpec{
			Actor: "human-shell", Connection: "c", Capability: "inject", Command: cmd, TTL: time.Hour,
		}, tempEnv(t))
		if err == nil || !strings.Contains(err.Error(), "wildcard") {
			t.Errorf("Create(%q) = %v, want a wildcard error", cmd, err)
		}
	}
}

func TestCreateRejectsRelativeScopes(t *testing.T) {
	for _, spec := range []grant.GrantSpec{
		{Command: "./npm test"},
		{CWD: "repo/*"},
	} {
		spec.Actor, spec.Connection, spec.Capability, spec.TTL = "human-shell", "c", "inject", time.Hour
		if _, err := grant.Create(context.Background(), spec, tempEnv(t)); err == nil {
			t.Errorf("Create(%+v) accepted a relative scope", spec)
		}
	}
}

func TestCWDScopeFollowsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs extra privileges on Windows")
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	outside := filepath.Join(root, "outside")
	mkdirs(t, repo, outside)
	link := filepath.Join(repo, "r")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "inside-link")
	if err := os.Symlink(repo, inside); err != nil {
		t.Fatal(err)
	}

	req := grant.FindRequest{Actor: "human-shell", Connection: "c", Capability: "inject", CWD: link}
	if findWithGrant(t, grant.GrantSpec{CWD: repo + "/*"}, req) {
		t.Fatal("a symlink inside the granted tree let a directory outside it match")
	}
	req.CWD = inside
	if !findWithGrant(t, grant.GrantSpec{CWD: repo + "/*"}, req) {
		t.Fatal("a symlink that resolves into the granted tree did not match")
	}
}

func TestCWDScopeCaseFolding(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "Repo")
	mkdirs(t, repo)
	upper := filepath.Join(filepath.Dir(repo), "REPO")
	if _, err := os.Stat(upper); err != nil {
		t.Skipf("file system is case-sensitive here: %v", err)
	}
	req := grant.FindRequest{Actor: "human-shell", Connection: "c", Capability: "inject", CWD: upper}
	want := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	if got := findWithGrant(t, grant.GrantSpec{CWD: repo}, req); got != want {
		t.Fatalf("Find with a case variant = %v, want %v on %s", got, want, runtime.GOOS)
	}
}

func TestCreateCapsTTL(t *testing.T) {
	_, err := grant.Create(context.Background(), grant.GrantSpec{
		Actor: "human-shell", Connection: "prod", Capability: "inject", TTL: 87600 * time.Hour,
	}, tempEnv(t))
	if !errors.Is(err, grant.ErrTTLTooLong) {
		t.Fatalf("Create with a ten-year TTL = %v, want ErrTTLTooLong", err)
	}
}
