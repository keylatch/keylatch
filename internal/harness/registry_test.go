package harness

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSignalsMatchProfiles pins the variables and executable names each
// harness sets, as observed in the harnesses' documentation and behaviour.
// The fake-agent profiles file will become the shared source for these
// values once the fake-agent harness exists.
func TestSignalsMatchProfiles(t *testing.T) {
	want := map[string]struct {
		env, exe []string
	}{
		"claude-code": {[]string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"}, []string{"claude"}},
		"codex":       {[]string{"CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED"}, []string{"codex"}},
		"cursor":      {[]string{"CURSOR_AGENT", "CURSOR_TRACE_ID"}, []string{"cursor-agent"}},
		"gemini-cli":  {[]string{"GEMINI_CLI"}, []string{"gemini"}},
		"opencode":    {[]string{"OPENCODE"}, []string{"opencode"}},
		"aider":       {nil, []string{"aider"}},
		"copilot-cli": {nil, []string{"copilot"}},
	}
	all := All()
	if len(all) != len(want) {
		t.Fatalf("got %d harnesses, want %d", len(all), len(want))
	}
	for _, d := range all {
		w, ok := want[d.ID]
		if !ok {
			t.Fatalf("unexpected harness %q", d.ID)
		}
		var env []string
		for _, s := range d.Env {
			env = append(env, s.Name)
		}
		if !slices.Equal(env, w.env) || !slices.Equal(d.Executables, w.exe) {
			t.Errorf("%s: env %v exe %v, want env %v exe %v", d.ID, env, d.Executables, w.env, w.exe)
		}
	}
}

func TestLookupAndByExecutable(t *testing.T) {
	if d, ok := Lookup("codex"); !ok || d.Name != "Codex CLI" {
		t.Fatalf("Lookup(codex) = %+v, %v", d, ok)
	}
	if _, ok := Lookup("windsurf"); ok {
		t.Fatal("Windsurf is not a detected harness")
	}
	for name, id := range map[string]string{
		"claude": "claude-code", "/usr/local/bin/claude": "claude-code", `C:\Tools\Claude.EXE`: "claude-code",
		"cursor-agent": "cursor", "gemini": "gemini-cli",
	} {
		if d, ok := ByExecutable(name); !ok || d.ID != id {
			t.Errorf("ByExecutable(%q) = %q, %v; want %q", name, d.ID, ok, id)
		}
	}
	for _, name := range []string{"", "bash", "claude-helper", "node"} {
		if _, ok := ByExecutable(name); ok {
			t.Errorf("ByExecutable(%q) must not match", name)
		}
	}
}

func TestMatch(t *testing.T) {
	if !NonEmpty.Fires("0") || NonEmpty.Fires("") {
		t.Fatal("NonEmpty")
	}
	if NotZero.Fires("0") || NotZero.Fires("") || !NotZero.Fires("yes") {
		t.Fatal("NotZero")
	}
}

func TestSignalsUniqueAndOrdered(t *testing.T) {
	seen := map[string]bool{}
	var legacySeen bool
	for _, s := range Signals() {
		if seen[s.Name] {
			t.Fatalf("duplicate signal %q", s.Name)
		}
		seen[s.Name] = true
		if s.Legacy {
			legacySeen = true
		} else if legacySeen && s.Harness != "" {
			t.Fatalf("current signal %q listed after a legacy alias", s.Name)
		}
	}
}

// TestSingleSourceOfHarnessNames fails when non-test Go code outside this
// package spells a harness environment variable as a string literal.
func TestSingleSourceOfHarnessNames(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range Signals() {
		names = append(names, `"`+s.Name+`"`)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", ".worktrees", "web", "src-tauri":
				return filepath.SkipDir
			}
			if path == self {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range names {
			if strings.Contains(string(data), n) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s spells %s; derive it from internal/harness", rel, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
