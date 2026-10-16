package targets

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	keysync "github.com/keylatch/keylatch/internal/sync"
)

var testValue = "value" + "-for-test-" + "7d1"

func TestSyncVercelUpsertTypes(t *testing.T) {
	f := &fakeVercel{token: "tok", team: "team_1"}
	f.envs = []*fakeVercelEnv{
		{ID: "e_branch", Key: "BRANCHED", Type: "encrypted", Targets: []string{"preview"}, GitBranch: "main"},
		{ID: "e_integ", Key: "INTEG", Type: "encrypted", Targets: []string{"production"}, Integration: "icfg_1"},
		{ID: "e_sys", Key: "VERCEL_URL", Type: "system", Targets: []string{"production"}},
	}
	v := NewVercel("prj_1", "team_1", staticToken("tok"), clientFor(t, f))
	ctx := context.Background()

	if err := v.Write(ctx, "DATABASE_URL", []byte(testValue), []string{"production", "preview"}, true); err != nil {
		t.Fatal(err)
	}
	if err := v.Write(ctx, "DEBUG", []byte("1"), []string{"development"}, false); err != nil {
		t.Fatal(err)
	}
	rs, err := v.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]keysync.Remote{}
	for _, r := range rs {
		byName[r.Name] = r
	}
	if r := byName["DATABASE_URL"]; r.Type != "sensitive" || !slices.Equal(r.Environments, []string{"production", "preview"}) || r.Unmanaged {
		t.Fatalf("DATABASE_URL = %+v", r)
	}
	if r := byName["DEBUG"]; r.Type != "encrypted" || !slices.Equal(r.Environments, []string{"development"}) {
		t.Fatalf("DEBUG = %+v", r)
	}
	for _, n := range []string{"BRANCHED", "INTEG", "VERCEL_URL"} {
		if !byName[n].Unmanaged {
			t.Errorf("%s must be reported but unmanaged", n)
		}
	}
	if got, ok, err := v.Readback(ctx, byName["DEBUG"]); err != nil || !ok || string(got) != "1" {
		t.Fatalf("readback of an encrypted entry: %q %v %v", got, ok, err)
	}
	if _, ok, _ := v.Readback(ctx, byName["DATABASE_URL"]); ok {
		t.Fatal("a sensitive entry was read back")
	}
	if v.ID() != "vercel:prj_1" {
		t.Fatal(v.ID())
	}
	if err := v.Delete(ctx, byName["DEBUG"]); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, byName["DEBUG"]); !IsNotFound(err) {
		t.Fatalf("second delete: %v", err)
	}
	posts := f.posts
	if err := v.Write(ctx, "DATABASE_URL", []byte(testValue+"2"), []string{"production", "preview"}, true); err != nil || f.posts != posts+1 || len(f.envs) != 4 {
		t.Fatalf("upsert must update in place: %v entries %d", err, len(f.envs))
	}
}

func TestSyncVercelPaginatesAndReportsErrors(t *testing.T) {
	f := &fakeVercel{token: "tok", pages: true, envs: []*fakeVercelEnv{
		{ID: "a", Key: "A", Type: "encrypted", Targets: []string{"production"}},
		{ID: "b", Key: "B", Type: "encrypted", Targets: []string{"production"}},
	}}
	ctx := context.Background()
	v := NewVercel("prj", "", staticToken("tok"), clientFor(t, f))
	rs, err := v.List(ctx)
	if err != nil || len(rs) != 2 {
		t.Fatalf("pagination: %v %v", rs, err)
	}
	bad := NewVercel("prj", "", staticToken("wrong"), clientFor(t, f))
	_, err = bad.List(ctx)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusForbidden || he.Code != "forbidden" || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v", err)
	}
	noTok := NewVercel("prj", "", func(context.Context) (string, error) { return "", errors.New("no credential") }, clientFor(t, f))
	if _, err := noTok.List(ctx); err == nil {
		t.Fatal("a missing credential was ignored")
	}
}

func TestSyncGitHubSealedBox(t *testing.T) {
	f := newFakeGitHub(t, "gh")
	g := NewGitHub("acme", "app", []string{"production"}, staticToken("gh"), clientFor(t, f))
	ctx := context.Background()
	if err := g.Write(ctx, "API_KEY", []byte(testValue), []string{keysync.EnvRepository, "production"}, true); err != nil {
		t.Fatal(err)
	}
	if f.secrets["repository"]["API_KEY"] != testValue || f.secrets["production"]["API_KEY"] != testValue {
		t.Fatalf("the fake could not decrypt the sealed values: %v", f.secrets)
	}
	rs, err := g.List(ctx)
	if err != nil || len(rs) != 2 {
		t.Fatalf("list: %v %v", rs, err)
	}
	for _, r := range rs {
		if r.UpdatedAt.IsZero() || len(r.Environments) != 1 {
			t.Fatalf("remote = %+v", r)
		}
	}
	if _, ok, _ := g.Readback(ctx, rs[0]); ok {
		t.Fatal("GitHub never returns a value")
	}
	if g.ID() != "github:acme/app" {
		t.Fatal(g.ID())
	}
	if err := g.Delete(ctx, keysync.Remote{Name: "API_KEY", Environments: []string{"production"}}); err != nil {
		t.Fatal(err)
	}
	if err := g.Delete(ctx, keysync.Remote{Name: "API_KEY", Environments: []string{"production"}}); err != nil {
		t.Fatalf("deleting an absent secret must succeed: %v", err)
	}
	if f.secrets["production"]["API_KEY"] != "" || f.secrets["repository"]["API_KEY"] == "" {
		t.Fatal("wrong scope deleted")
	}
}

func TestSyncGitHubPaginatesAndRejectsBadKey(t *testing.T) {
	f := newFakeGitHub(t, "gh")
	f.secrets["repository"] = map[string]string{}
	for i := 0; i < 130; i++ {
		f.secrets["repository"]["S"+strings.Repeat("X", i%7)+string(rune('A'+i%26))+string(rune('a'+i/26))] = "v"
		f.updated["repository/x"] = time.Now()
	}
	g := NewGitHub("acme", "app", nil, staticToken("gh"), clientFor(t, f))
	rs, err := g.List(context.Background())
	if err != nil || len(rs) != len(f.secrets["repository"]) || len(rs) < 101 {
		t.Fatalf("pagination: %d of %d %v", len(rs), len(f.secrets["repository"]), err)
	}
	f.badKey = true
	g = NewGitHub("acme", "app", nil, staticToken("gh"), clientFor(t, f))
	if err := g.Write(context.Background(), "A", []byte("v"), []string{keysync.EnvRepository}, true); err == nil {
		t.Fatal("a malformed public key was accepted")
	}
	wrong := NewGitHub("acme", "app", nil, staticToken("nope"), clientFor(t, f))
	if err := wrong.Write(context.Background(), "A", []byte("v"), []string{keysync.EnvRepository}, true); err == nil {
		t.Fatal("a rejected token was ignored")
	}
}

func TestSyncEnvFileKeepsUnmanagedLines(t *testing.T) {
	src := "# managed by hand\nexport KEEP=1\n\nDATABASE_URL=old\nOTHER = spaced\n"
	var saved []byte
	f := NewEnvFile("envfile:.env.local", []byte(src), func(b []byte) error { saved = b; return nil })
	ctx := context.Background()

	rs, _ := f.List(ctx)
	var names []string
	for _, r := range rs {
		names = append(names, r.Name)
	}
	if !slices.Equal(names, []string{"KEEP", "DATABASE_URL", "OTHER"}) {
		t.Fatalf("names = %v", names)
	}
	if err := f.Flush(ctx); err != nil || saved != nil {
		t.Fatal("an untouched file was written")
	}
	_ = f.Write(ctx, "DATABASE_URL", []byte("postgres://u:p@h/db?x=1"), nil, true)
	_ = f.Write(ctx, "TOKEN", []byte("has space"), nil, true)
	_ = f.Write(ctx, "MULTI", []byte("a\nb\"c"), nil, true)
	_ = f.Delete(ctx, keysync.Remote{Name: "OTHER"})
	if err := f.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	want := "# managed by hand\nexport KEEP=1\n\nDATABASE_URL=postgres://u:p@h/db?x=1\nTOKEN='has space'\nMULTI=\"a\\nb\\\"c\"\n"
	if string(saved) != want {
		t.Fatalf("content:\n%s\nwant:\n%s", saved, want)
	}
	if f.ID() != "envfile:.env.local" {
		t.Fatal(f.ID())
	}
	if _, ok, _ := f.Readback(ctx, keysync.Remote{}); ok {
		t.Fatal("readback")
	}
	failing := NewEnvFile("x", nil, func([]byte) error { return errors.New("disk full") })
	_ = failing.Write(ctx, "A", []byte("1"), nil, true)
	if err := failing.Flush(ctx); err == nil {
		t.Fatal("a failed write was ignored")
	}
	if got := NewEnvFile("x", []byte("A=1\r\nB=2"), nil); string(got.Content()) != "A=1\nB=2\n" && string(got.Content()) != "A=1\nB=2" {
		t.Fatalf("crlf: %q", got.Content())
	}
	if NewEnvFile("x", nil, nil).Content() != nil {
		t.Fatal("empty file content")
	}
	if !slices.Equal(Keys([]byte("A=1\n# B=2\nexport C=3\n")), []string{"A", "C"}) {
		t.Fatal("Keys")
	}
}
