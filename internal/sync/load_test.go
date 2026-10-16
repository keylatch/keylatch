package sync

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fakeGit(root string, ignored, tracked bool) Git {
	return func(_ string, args ...string) (string, int) {
		switch args[0] {
		case "rev-parse":
			return root, 0
		case "check-ignore":
			if ignored {
				return "", 0
			}
			return "", 1
		case "ls-files":
			if tracked {
				return "", 0
			}
			return "", 1
		}
		return "", -1
	}
}

func writeRepo(t *testing.T, manifest string) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(root, DefaultFile), []byte(manifest), 0o600))
	must(os.WriteFile(filepath.Join(root, ".env.local"), []byte("A=1\nexport B=2\n# C=3\n"), 0o600))
	must(os.MkdirAll(filepath.Join(root, ".vercel"), 0o700))
	must(os.WriteFile(filepath.Join(root, ".vercel", "project.json"), []byte(`{"projectId":"prj_9","orgId":"team_7"}`), 0o600))
	return root
}

const linkManifest = `version: 1
targets:
  web:   {type: vercel, link: .vercel/project.json, credential: v}
  local: {type: env-file, path: .env.local}
vars:
  - {name: A, from: {connection: c}, to: {web: [production], local: [file]}}
`

func TestLoadReadsLinksAndEnvKeys(t *testing.T) {
	root := writeRepo(t, linkManifest)
	l, err := Load("", root, fakeGit(root, true, false))
	if err != nil {
		t.Fatal(err)
	}
	if l.Root != root || l.Links["web"] != "prj_9" || l.LinkTeams["web"] != "team_7" || !slices.Equal(l.EnvKeys["local"], []string{"A", "B"}) {
		t.Fatalf("loaded = %+v", l)
	}
	// --file names a manifest elsewhere; the repository is the one it lives in.
	l, err = Load(filepath.Join(root, DefaultFile), t.TempDir(), fakeGit(root, true, false))
	if err != nil || l.Root != root {
		t.Fatalf("explicit file: %v %v", l, err)
	}
	// Outside a repository the directory is the root and the git rules refuse the env file.
	notRepo := func(string, ...string) (string, int) { return "", 128 }
	if _, err := Load("", root, notRepo); err == nil || !strings.Contains(err.Error(), "git") {
		t.Fatalf("outside a repository: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	root := writeRepo(t, linkManifest)
	if _, err := Load("", t.TempDir(), fakeGit(t.TempDir(), true, false)); !errors.Is(err, ErrNoManifest) {
		t.Fatalf("missing manifest: %v", err)
	}
	if err := os.Remove(filepath.Join(root, ".vercel", "project.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("", root, fakeGit(root, true, false)); err == nil || !strings.Contains(err.Error(), "targets.web.link") {
		t.Fatalf("missing link: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".vercel", "project.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("", root, fakeGit(root, true, false)); err == nil {
		t.Fatal("a link without a project")
	}
	if _, err := Load("", root, fakeGit(root, false, false)); err == nil || !strings.Contains(err.Error(), "not git-ignored") {
		t.Fatalf("unignored env file: %v", err)
	}
	if _, err := Load("", root, fakeGit(root, true, true)); err == nil || !strings.Contains(err.Error(), "tracked") {
		t.Fatalf("tracked env file: %v", err)
	}
	bad := writeRepo(t, "version: 1\nnope: 1\n")
	if _, err := Load("", bad, fakeGit(bad, true, false)); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("bad manifest: %v", err)
	}
	os.WriteFile(filepath.Join(root, ".vercel", "project.json"), []byte(`{"projectId":"p","orgId":"user_1"}`), 0o600)
	if _, team, err := ReadVercelLink(filepath.Join(root, ".vercel", "project.json")); err != nil || team != "" {
		t.Fatalf("personal link: %q %v", team, err)
	}
}

func TestFindPath(t *testing.T) {
	have := []string{"vercel/token", "plain", "default/cloud/aws/secret", "other/cloud/aws/secret", "default/ci/gh/api_key"}
	cases := []struct {
		conn   string
		fields []string
		want   string
		err    string
	}{
		{"vercel", []string{"token"}, "vercel/token", ""},
		{"plain", []string{""}, "plain", ""},
		{"gh", []string{"api_key"}, "default/ci/gh/api_key", ""},
		{"aws", []string{"secret"}, "", "ambiguous"},
		{"none", []string{"token", ""}, "", "no stored value"},
	}
	for _, tc := range cases {
		got, err := FindPath(have, tc.conn, tc.fields)
		if tc.err == "" && (err != nil || got != tc.want) || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: %q %v", tc.conn, got, err)
		}
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize([]byte(goodManifest), "", "")
	for _, want := range []string{"web (vercel): 2 name(s) DATABASE_URL, FLAG", "ci (github-actions): 1 name(s) DATABASE_URL", "local (env-file)"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q lacks %q", s, want)
		}
	}
	if s := Summarize([]byte(goodManifest), "FLAG", ""); strings.Contains(s, "ci") || !strings.Contains(s, "web (vercel): 1 name(s) FLAG") {
		t.Errorf("only FLAG: %q", s)
	}
	if s := Summarize([]byte(goodManifest), "", "ci"); strings.Contains(s, "web") {
		t.Errorf("only ci: %q", s)
	}
	if Summarize([]byte("nope"), "", "") == "" || Summarize([]byte(goodManifest), "ABSENT", "") != "no targets" {
		t.Error("degenerate summaries")
	}
}
