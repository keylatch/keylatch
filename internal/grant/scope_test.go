package grant_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/grant"
)

func TestFindEnforcesGrantScope(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	other := filepath.Join(filepath.Dir(repo), "repo-other")

	base := grant.FindRequest{
		Actor:      "human-shell",
		Connection: "openrouter:dev",
		Capability: "inject",
		Command:    []string{"npm", "test"},
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
		{name: "exact command matches", command: "npm test", want: true},
		{name: "other command rejected", command: "npm test", mutate: func(r *grant.FindRequest) { r.Command = []string{"curl", "evil"} }},
		{name: "no implicit argument extension", command: "npm test", mutate: func(r *grant.FindRequest) { r.Command = []string{"npm", "test", "--", "x"} }},
		{name: "explicit trailing wildcard extends", command: "npm test*", mutate: func(r *grant.FindRequest) { r.Command = []string{"npm", "test", "--", "x"} }, want: true},
		{name: "restricted command needs a command", command: "npm test", mutate: func(r *grant.FindRequest) { r.Command = nil }},
		{name: "exact cwd matches", cwd: repo, want: true},
		{name: "other cwd rejected", cwd: repo, mutate: func(r *grant.FindRequest) { r.CWD = other }},
		{name: "subtree cwd matches subdirectory", cwd: repo + "/*", mutate: func(r *grant.FindRequest) { r.CWD = filepath.Join(repo, "pkg", "a") }, want: true},
		{name: "subtree cwd matches its root", cwd: repo + "/*", want: true},
		{name: "subtree cwd rejects sibling prefix", cwd: repo + "/*", mutate: func(r *grant.FindRequest) { r.CWD = other }},
		{name: "subtree cwd rejects parent", cwd: repo + "/*", mutate: func(r *grant.FindRequest) { r.CWD = filepath.Dir(repo) }},
		{name: "restricted cwd needs a cwd", cwd: repo, mutate: func(r *grant.FindRequest) { r.CWD = "" }},
		{name: "empty actor does not match restricted grant", mutate: func(r *grant.FindRequest) { r.Actor = "" }},
		{name: "empty connection does not match restricted grant", mutate: func(r *grant.FindRequest) { r.Connection = "" }},
		{name: "empty capability does not match restricted grant", mutate: func(r *grant.FindRequest) { r.Capability = "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tempEnv(t)
			ctx := context.Background()
			if _, err := grant.Create(ctx, grant.GrantSpec{
				Actor:      base.Actor,
				Connection: base.Connection,
				Capability: base.Capability,
				Command:    tc.command,
				CWD:        tc.cwd,
				TTL:        time.Hour,
			}, env); err != nil {
				t.Fatalf("Create: %v", err)
			}
			req := base
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			_, ok := grant.Find(ctx, env("KEYLATCH_GRANTS_PATH"), req)
			if ok != tc.want {
				t.Fatalf("Find = %v, want %v", ok, tc.want)
			}
		})
	}
}
