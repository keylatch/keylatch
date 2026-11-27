package harness

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func envWith(home string, vars map[string]string) Env {
	return Env{Home: home, Getenv: func(k string) string { return vars[k] }}
}

func mustLookup(t *testing.T, id string) Descriptor {
	t.Helper()
	d, ok := Lookup(id)
	if !ok {
		t.Fatalf("no harness %q", id)
	}
	return d
}

func TestDirHonoursEnvironmentOverrides(t *testing.T) {
	home := filepath.FromSlash("/home/u")
	for _, tc := range []struct {
		id   string
		vars map[string]string
		want string
	}{
		{"claude-code", nil, filepath.Join(home, ".claude")},
		{"claude-code", map[string]string{"CLAUDE_CONFIG_DIR": "/alt/claude"}, filepath.Clean("/alt/claude")},
		{"claude-code", map[string]string{"CLAUDE_CONFIG_DIR": "  "}, filepath.Join(home, ".claude")},
		{"codex", map[string]string{"CODEX_HOME": "/alt/codex"}, filepath.Clean("/alt/codex")},
		{"codex", nil, filepath.Join(home, ".codex")},
		{"gemini-cli", map[string]string{"GEMINI_CLI_HOME": "/alt"}, filepath.Join("/alt", ".gemini")},
		{"gemini-cli", nil, filepath.Join(home, ".gemini")},
		{"opencode", nil, filepath.Join(home, ".config", "opencode")},
		{"opencode", map[string]string{"XDG_CONFIG_HOME": "/xdg"}, filepath.Join("/xdg", "opencode")},
		{"copilot-cli", map[string]string{"COPILOT_HOME": "/alt/copilot"}, filepath.Clean("/alt/copilot")},
		{"windsurf", nil, filepath.Join(home, ".codeium", "windsurf")},
	} {
		if got := mustLookup(t, tc.id).Dir(envWith(home, tc.vars)); got != tc.want {
			t.Errorf("%s with %v: Dir = %q, want %q", tc.id, tc.vars, got, tc.want)
		}
	}
}

func TestLayoutFiles(t *testing.T) {
	home := filepath.FromSlash("/home/u")
	claude := mustLookup(t, "claude-code")

	l := claude.Layout(envWith(home, nil))
	if l.Hook != filepath.Join(home, ".claude", "settings.json") || l.MCP != filepath.Join(home, ".claude.json") || l.Rules != filepath.Join(home, ".claude", "CLAUDE.md") {
		t.Errorf("default layout: %+v", l)
	}
	// With the directory overridden the MCP file moves in with it.
	l = claude.Layout(envWith(home, map[string]string{"CLAUDE_CONFIG_DIR": "/alt"}))
	if l.MCP != filepath.Join(filepath.Clean("/alt"), ".claude.json") {
		t.Errorf("overridden layout: %+v", l)
	}

	proj := filepath.FromSlash("/work/app")
	pl := claude.Layout(Env{Home: home, Project: proj})
	if pl.Hook != filepath.Join(proj, ".claude", "settings.json") || pl.Rules != filepath.Join(proj, "CLAUDE.md") || pl.MCP != "" {
		t.Errorf("project layout: %+v", pl)
	}
	cursor := mustLookup(t, "cursor")
	if cl := cursor.Layout(envWith(home, nil)); cl.Rules != "" {
		t.Errorf("Cursor has no user-level rules file: %+v", cl)
	}
	if cl := cursor.Layout(Env{Project: proj}); cl.Rules != filepath.Join(proj, ".cursor", "rules", "keylatch.mdc") {
		t.Errorf("Cursor project rules: %+v", cl)
	}
	if aider := mustLookup(t, "aider").Layout(envWith(home, nil)); aider.Hook != "" || aider.MCP != "" || aider.Rules != "" {
		t.Errorf("a launch-only harness has no files: %+v", aider)
	}
}

func TestSystemEnvReadsTheProcess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	t.Setenv("CODEX_HOME", filepath.Join(os.Getenv("HOME"), "cx"))
	e, err := SystemEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got := mustLookup(t, "codex").Dir(e); got != filepath.Join(os.Getenv("HOME"), "cx") {
		t.Errorf("Dir = %q", got)
	}
}

func TestResolveAcceptsTheSpellingsPeopleType(t *testing.T) {
	for in, want := range map[string]string{
		"claude-code": "claude-code", "Claude_Code": "claude-code", "claudecode": "claude-code", "claude": "claude-code",
		"gemini": "gemini-cli", "copilot": "copilot-cli", " cursor ": "cursor", "agy": "antigravity",
	} {
		if d, ok := Resolve(in); !ok || d.ID != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", in, d.ID, ok, want)
		}
	}
	if _, ok := Resolve("emacs"); ok {
		t.Error("emacs is not a harness")
	}
}

func TestEveryDescriptorIsCompleteForItsSupportLevel(t *testing.T) {
	adapters := map[string]bool{}
	for _, d := range All() {
		switch d.Support {
		case SupportGuard:
			if d.Hook == nil || d.MCP == nil || d.Rules == nil || d.Adapter == "" || len(d.Hook.Events) == 0 {
				t.Errorf("%s supports a guard but misses a hook, MCP, rules or adapter entry", d.ID)
			}
			if adapters[d.Adapter] {
				t.Errorf("adapter %q is used twice", d.Adapter)
			}
			adapters[d.Adapter] = true
		case SupportLaunchOnly:
			if d.Hook != nil || d.MCP != nil || d.Rules != nil || len(d.Executables) == 0 {
				t.Errorf("%s is launch-only but has config files or no executable", d.ID)
			}
		default:
			t.Errorf("%s has support level %q", d.ID, d.Support)
		}
		if d.Name == "" {
			t.Errorf("%s has no name", d.ID)
		}
	}
	if got := len(Installable()); got != len(adapters) {
		t.Errorf("%d installable harnesses, %d adapters", got, len(adapters))
	}
}

func TestHelpersDeriveFromTheTable(t *testing.T) {
	dirs := ConfigDirNames()
	for _, want := range []string{".claude", ".codex", ".gemini", ".cursor", ".copilot", ".codeium/windsurf", ".config/opencode"} {
		if !slices.Contains(dirs, want) {
			t.Errorf("ConfigDirNames misses %q: %v", want, dirs)
		}
	}
	files := ProtectedFiles()
	for _, want := range []string{
		".claude/settings.json", ".claude/settings.local.json", ".claude/hooks/", "managed-settings.json", ".claude.json",
		".codex/hooks.json", ".codex/config.toml", ".cursor/hooks.json", ".cursor/mcp.json", ".gemini/settings.json",
		".config/opencode/plugins/keylatch-guard.ts", ".config/opencode/opencode.json", ".copilot/hooks/keylatch-guard.json",
		".codeium/windsurf/hooks.json", ".gemini/config/hooks.json", ".github/hooks/keylatch-guard.json",
	} {
		if !slices.Contains(files, want) {
			t.Errorf("ProtectedFiles misses %q", want)
		}
	}
	if got := mustLookup(t, "cursor").HookDisplay(); got != "~/.cursor/hooks.json" {
		t.Errorf("HookDisplay = %q", got)
	}
	if got := mustLookup(t, "aider").HookDisplay(); got != "" {
		t.Errorf("a launch-only harness has no hook: %q", got)
	}
}

// harnessPathRe matches a Go string literal that spells a harness configuration
// directory or one of the files in it.
var harnessPathRe = regexp.MustCompile(`"[^"\n]*\.(claude|codex|cursor|gemini|copilot|codeium|opencode|windsurf)([/".][^"\n]*)?"`)

// TestSingleSourceOfHarnessPaths fails when non-test Go code outside this
// package spells a harness configuration path as a string literal.
func TestSingleSourceOfHarnessPaths(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	self, _ := filepath.Abs(".")
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
		for i, line := range strings.Split(string(data), "\n") {
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
				continue
			}
			if m := harnessPathRe.FindString(line); m != "" {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d spells the harness path %s; derive it from internal/harness", rel, i+1, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
