package targets

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	keysync "github.com/keylatch/keylatch/internal/sync"
)

const buildManifest = `version: 1
targets:
  web:   {type: vercel, link: .vercel/project.json, credential: v}
  ci:    {type: github-actions, repo: acme/app, environments: [production], credential: g}
  local: {type: env-file, path: .env.local}
vars:
  - {name: A, from: {connection: c}, to: {web: [production], ci: [repository], local: [file]}}
`

func TestBuildTargets(t *testing.T) {
	m, err := keysync.Parse([]byte(buildManifest), nil)
	if err != nil {
		t.Fatal(err)
	}
	cred := func(_ context.Context, c string) (string, error) { return "tok-" + c, nil }
	var flushed []byte
	cs, err := Build(m, BuildOptions{
		Credential: cred, Links: map[string]string{"web": "prj_9"}, LinkTeams: map[string]string{"web": "team_1"}, Root: "/repo",
		EnvFiles: map[string]EnvFileIO{"local": {Existing: []byte("KEEP=1\n"), Flush: func(b []byte) error { flushed = b; return nil }}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cs["web"].ID() != "vercel:prj_9" || cs["ci"].ID() != "github:acme/app" || cs["local"].ID() != "envfile:/repo/.env.local" {
		t.Fatalf("ids: %s %s %s", cs["web"].ID(), cs["ci"].ID(), cs["local"].ID())
	}
	ctx := context.Background()
	if err := cs["local"].Write(ctx, "A", []byte("v"), nil, true); err != nil {
		t.Fatal(err)
	}
	if err := cs["local"].(keysync.Flusher).Flush(ctx); err != nil || string(flushed) != "KEEP=1\nA=v\n" {
		t.Fatalf("flushed %q %v", flushed, err)
	}

	// A link the client did not read is an error, not an empty project.
	if _, err := Build(m, BuildOptions{Credential: cred}); err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatalf("unresolved link: %v", err)
	}

	// An env file whose content was not handed over lists names and refuses writes.
	cs, err = Build(m, BuildOptions{Credential: cred, Links: map[string]string{"web": "p"}, Root: "/r", EnvKeys: map[string][]string{"local": {"X", "Y"}}})
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := cs["local"].List(ctx)
	if len(rs) != 2 || rs[0].Name != "X" || !slices.Equal(rs[0].Environments, []string{keysync.EnvFile}) {
		t.Fatalf("names = %+v", rs)
	}
	if cs["local"].Write(ctx, "A", nil, nil, true) == nil || cs["local"].Delete(ctx, keysync.Remote{}) == nil {
		t.Fatal("a names-only target accepted a change")
	}
	if _, ok, err := cs["local"].Readback(ctx, keysync.Remote{}); ok || err != nil {
		t.Fatal("readback")
	}

	// An override replaces the client; the token function it receives reads the credential.
	var got string
	cs, err = Build(m, BuildOptions{
		Credential: cred, Links: map[string]string{"web": "p"},
		Override: func(name string, _ keysync.Target, tok Token) (keysync.TargetClient, bool) {
			if name == "ci" {
				got, _ = tok(ctx)
				return NamesOnly{TargetID: "fake"}, true
			}
			return nil, false
		},
	})
	if err != nil || cs["ci"].ID() != "fake" || got != "tok-g" {
		t.Fatalf("override: %v %q", err, got)
	}
}

func TestHTTPErrorsAndOptions(t *testing.T) {
	e := &HTTPError{Method: "GET", Path: "/x", Status: 500}
	if !strings.Contains(e.Error(), "500") || strings.Contains(e.Error(), "(") {
		t.Fatal(e.Error())
	}
	if IsNotFound(errors.New("x")) || !IsNotFound(&HTTPError{Status: 404}) {
		t.Fatal("IsNotFound")
	}
	if (Options{}).client().Timeout == 0 {
		t.Fatal("the default client needs a timeout")
	}
}

func TestGitHubEnvironmentScopesAndErrors(t *testing.T) {
	f := newFakeGitHub(t, "gh")
	g := NewGitHub("acme", "app", []string{"production"}, staticToken("gh"), clientFor(t, f))
	ctx := context.Background()
	// An environment secret needs the repository id and the environment key.
	if err := g.Write(ctx, "ENV_ONLY", []byte("v"), []string{"production"}, true); err != nil {
		t.Fatal(err)
	}
	if f.secrets["production"]["ENV_ONLY"] != "v" {
		t.Fatalf("secrets = %v", f.secrets)
	}
	rs, err := g.List(ctx)
	if err != nil || len(rs) != 1 || rs[0].Environments[0] != "production" {
		t.Fatalf("list = %+v %v", rs, err)
	}
	missingRepo := NewGitHub("nobody", "none", []string{"production"}, staticToken("gh"), clientFor(t, f))
	if err := missingRepo.Write(ctx, "A", []byte("v"), []string{"production"}, true); err == nil {
		t.Fatal("write to an unknown repository")
	}
	if err := missingRepo.Delete(ctx, keysync.Remote{Name: "A", Environments: []string{"repository"}}); err != nil {
		t.Fatalf("delete of an absent secret: %v", err)
	}
	if err := g.Delete(ctx, keysync.Remote{Name: "X", Environments: []string{"repository"}}); err != nil {
		t.Fatalf("delete of an absent secret: %v", err)
	}
	if _, ok, err := NewVercel("p", "", staticToken("t"), clientFor(t, &fakeVercel{token: "t"})).Readback(ctx, keysync.Remote{ID: "nope", Type: "encrypted"}); ok || err == nil {
		t.Fatalf("readback of a missing entry: %v %v", ok, err)
	}
}
