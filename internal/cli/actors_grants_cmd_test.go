package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/grant"
)

func cdReadActors(t *testing.T, dir string) []actorEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "actors.json"))
	if err != nil {
		t.Fatalf("read actors: %v", err)
	}
	var a []actorEntry
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestActors_Lifecycle(t *testing.T) {
	dir := cdIsolate(t)

	r := cdExec(t, newActorsCmd(), nil, "list")
	if r.e != nil || strings.TrimSpace(r.out) != "NAME  NOTE  CREATED" {
		t.Fatalf("empty list: err=%v out=%q", r.e, r.out)
	}

	r = cdExec(t, newActorsCmd(), nil, "create", "ci-bot", "--note", "pipeline")
	if r.e != nil || !strings.Contains(r.out, `actor "ci-bot" created`) {
		t.Fatalf("create: err=%v out=%q", r.e, r.out)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(filepath.Join(dir, "actors.json")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("actors file must be 0600: %v %v", fi, err)
		}
	}
	if r = cdExec(t, newActorsCmd(), nil, "create", "ci-bot"); r.e == nil || !strings.Contains(r.e.Error(), "already exists") {
		t.Fatalf("duplicate create: err=%v", r.e)
	}
	if r = cdExec(t, newActorsCmd(), nil, "create", "other"); r.e != nil {
		t.Fatal(r.e)
	}

	r = cdExec(t, newActorsCmd(), nil, "list", "--json")
	var listed []actorEntry
	if err := json.Unmarshal([]byte(r.out), &listed); err != nil || len(listed) != 2 || listed[0].Note != "pipeline" {
		t.Fatalf("json list: %v %q", err, r.out)
	}
	r = cdExec(t, newActorsCmd(), nil, "list")
	if !strings.Contains(r.out, "ci-bot") || !strings.Contains(r.out, "pipeline") {
		t.Fatalf("table list: %q", r.out)
	}

	r = cdExec(t, newActorsCmd(), nil, "rename", "ci-bot", "deploy-bot")
	if r.e != nil || !strings.Contains(r.out, `actor "ci-bot" renamed to "deploy-bot"`) {
		t.Fatalf("rename: err=%v out=%q", r.e, r.out)
	}
	r = cdExec(t, newActorsCmd(), nil, "delete", "other")
	if r.e != nil || !strings.Contains(r.out, `actor "other" deleted`) {
		t.Fatalf("delete: err=%v out=%q", r.e, r.out)
	}
	got := cdReadActors(t, dir)
	if len(got) != 1 || got[0].Name != "deploy-bot" || got[0].Note != "pipeline" {
		t.Fatalf("unexpected actors %+v", got)
	}
	if r = cdExec(t, newActorsCmd(), nil, "delete", "deploy-bot"); r.e != nil {
		t.Fatal(r.e)
	}
	if got := cdReadActors(t, dir); len(got) != 0 {
		t.Fatalf("expected empty actor list, got %+v", got)
	}
}

func TestActors_RejectsInvalidAndUnknownNames(t *testing.T) {
	dir := cdIsolate(t)
	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"create uppercase", []string{"create", "Bad"}, "is invalid"},
		{"create path traversal", []string{"create", "../x"}, "is invalid"},
		{"rename to invalid", []string{"rename", "a", "Has Space"}, "is invalid"},
		{"rename unknown", []string{"rename", "ghost", "spirit"}, `actor "ghost" not found`},
		{"delete unknown", []string{"delete", "ghost"}, `actor "ghost" not found`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := cdExec(t, newActorsCmd(), nil, tc.args...)
			if r.e == nil || !strings.Contains(r.e.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", r.e, tc.wantErr)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "actors.json")); !os.IsNotExist(err) {
		t.Fatal("rejected operations must not create the actors file")
	}
}

func TestActors_CorruptOrUnwritableStore(t *testing.T) {
	dir := cdIsolate(t)
	p := filepath.Join(dir, "actors.json")
	if err := os.WriteFile(p, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"list"}, {"create", "ok-name"}, {"delete", "x"}, {"rename", "x", "y"}} {
		if r := cdExec(t, newActorsCmd(), nil, args...); r.e == nil {
			t.Fatalf("%v must fail on a corrupt actors file", args)
		}
	}

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if r := cdExec(t, newActorsCmd(), nil, "list"); r.e == nil {
		t.Fatal("list must fail when the actors path is unreadable")
	}

	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYLATCH_ACTORS_PATH", filepath.Join(blocker, "actors.json"))
	if r := cdExec(t, newActorsCmd(), nil, "create", "ok-name"); r.e == nil {
		t.Fatal("create must fail when the actors dir cannot be created")
	}
}

func TestActorsGetDefault_ReportsOverride(t *testing.T) {
	cdIsolate(t)
	t.Setenv("KEYLATCH_ACTOR", "release-bot")
	r := cdExec(t, newActorsCmd(), nil, "get-default")
	if r.e != nil || !strings.HasPrefix(r.out, "release-bot (source: ") {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
}

func TestGrant_CreateListRevoke(t *testing.T) {
	dir := cdIsolate(t)
	withInteractiveStdin(t, true)

	withInteractiveStdin(t, false)
	r := cdExec(t, newGrantCmd(), nil, "create", "openai", "--actor", "ci")
	if r.e == nil || !strings.Contains(r.e.Error(), "requires an interactive terminal") {
		t.Fatalf("non-interactive create: err=%v", r.e)
	}
	withInteractiveStdin(t, true)
	r = cdExec(t, newGrantCmd(), nil, "create", "openai")
	if r.e == nil || !strings.Contains(r.e.Error(), "--actor is required") {
		t.Fatalf("missing actor: err=%v", r.e)
	}
	if r = cdExec(t, newGrantCmd(), nil, "create", "openai", "--actor", "ci", "--ttl", "eventually"); r.e == nil ||
		!strings.Contains(r.e.Error(), "invalid --ttl") {
		t.Fatalf("bad ttl: err=%v", r.e)
	}
	if _, err := os.Stat(filepath.Join(dir, "grants.json")); !os.IsNotExist(err) {
		t.Fatal("rejected grant must not write the grants file")
	}

	start := time.Now().UTC()
	r = cdExec(t, newGrantCmd(), nil, "create", "openai", "--actor", "ci", "--ttl", "30m", "--max-uses", "3", "--command", "curl *")
	if r.e != nil {
		t.Fatalf("create: %v", r.e)
	}
	if !strings.Contains(r.out, "max uses:      3") || !strings.Contains(r.out, "grant id:") {
		t.Fatalf("unexpected create output %q", r.out)
	}
	gs, err := grant.List(t.Context(), filepath.Join(dir, "grants.json"), grant.ListOpts{})
	if err != nil || len(gs) != 1 {
		t.Fatalf("list grants: %v %d", err, len(gs))
	}
	g := gs[0]
	if g.Actor != "ci" || g.Connection != "openai" || g.Capability != "inject" || g.MaxUses != 3 || g.Command != "curl *" {
		t.Fatalf("unexpected grant %+v", g)
	}
	if exp := g.ExpiresAt.Sub(start); exp < 29*time.Minute || exp > 31*time.Minute {
		t.Fatalf("expiry %v not ~30m", exp)
	}

	r = cdExec(t, newGrantCmd(), nil, "create", "github", "--actor", "ci")
	if r.e != nil || strings.Contains(r.out, "max uses") {
		t.Fatalf("unlimited grant: err=%v out=%q", r.e, r.out)
	}

	r = cdExec(t, newGrantCmd(), nil, "list")
	if r.e != nil || !strings.Contains(r.out, g.ID) || !strings.Contains(r.out, "github") {
		t.Fatalf("table list: err=%v out=%q", r.e, r.out)
	}

	r = cdExec(t, newGrantCmd(), nil, "revoke", g.ID)
	if r.e != nil || !strings.Contains(r.out, "grant "+g.ID+" revoked") {
		t.Fatalf("revoke: err=%v out=%q", r.e, r.out)
	}

	r = cdExec(t, newGrantCmd(), nil, "list", "--json")
	var rows []map[string]any
	if err := json.Unmarshal([]byte(r.out), &rows); err != nil || len(rows) != 1 || rows[0]["connection"] != "github" {
		t.Fatalf("revoked grant must be hidden by default: %v %q", err, r.out)
	}
	r = cdExec(t, newGrantCmd(), nil, "list", "--json", "--include-revoked", "--include-expired")
	rows = nil
	if err := json.Unmarshal([]byte(r.out), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("include-revoked list: %v %q", err, r.out)
	}
	for _, row := range rows {
		if row["id"] == g.ID && row["revoked"] != true {
			t.Fatalf("revoked flag missing: %v", row)
		}
	}

	if r = cdExec(t, newGrantCmd(), nil, "revoke", "no-such-grant"); r.e == nil || !strings.Contains(r.e.Error(), "not found") {
		t.Fatalf("unknown revoke: err=%v", r.e)
	}
}

func TestGrant_EmptyAndCorruptStore(t *testing.T) {
	dir := cdIsolate(t)
	withInteractiveStdin(t, true)
	r := cdExec(t, newGrantListCmd(), nil, "--json")
	if r.e != nil || strings.TrimSpace(r.out) != "[]" {
		t.Fatalf("empty json list: err=%v out=%q", r.e, r.out)
	}
	if err := os.WriteFile(filepath.Join(dir, "grants.json"), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r = cdExec(t, newGrantListCmd(), nil); r.e == nil || !strings.Contains(r.e.Error(), "grant list:") {
		t.Fatalf("corrupt list: err=%v", r.e)
	}
	if r = cdExec(t, newGrantRevokeCmd(), nil, "x"); r.e == nil || !strings.Contains(r.e.Error(), "grant revoke:") {
		t.Fatalf("corrupt revoke: err=%v", r.e)
	}
	if r = cdExec(t, newGrantCreateCmd(), nil, "openai", "--actor", "ci"); r.e == nil || !strings.Contains(r.e.Error(), "grant create:") {
		t.Fatalf("corrupt create: err=%v", r.e)
	}
}

func TestGenerateUUID_Version4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		id, err := generateUUID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 36 || id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
			t.Fatalf("not a v4 UUID: %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate UUID %q", id)
		}
		seen[id] = true
	}
}
