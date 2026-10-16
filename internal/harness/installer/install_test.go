package installer

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/harness/merge"
)

const (
	testBinary = "/opt/keylatch/bin/keylatch"
)

func lf(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }

func testEnv(home string) Env {
	return Env{Home: home, Getenv: func(string) string { return "" }}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, path)
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, []byte(lf(data)), 0o600)
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, path)
		out[filepath.ToSlash(rel)] = lf(data)
		return nil
	})
	return out
}

// installGolden installs into a copy of testdata/<id>/before and compares the
// result with testdata/<id>/after, file by file. Backups the installer saved are
// compared with the files they replaced.
func installGolden(t *testing.T, id string, parts Parts) {
	t.Helper()
	d, ok := harness.Lookup(id)
	if !ok {
		t.Fatalf("unknown harness %q", id)
	}
	before := filepath.Join("testdata", id, "before")
	home := t.TempDir()
	copyTree(t, before, home)
	original := readTree(t, home)

	opts := Options{
		Env: testEnv(home), Command: GuardCommand(d, testBinary), Binary: testBinary,
		Server: Server{Command: testBinary}, Parts: parts,
	}
	res, err := Install(d, opts)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	got := readTree(t, home)

	for name, content := range got {
		if !strings.HasSuffix(name, merge.BackupSuffix) {
			continue
		}
		source := strings.TrimSuffix(name, merge.BackupSuffix)
		if original[source] != content {
			t.Errorf("backup %s is not the file as it was before the install", name)
		}
		delete(got, name)
	}

	want := readTree(t, filepath.Join("testdata", id, "after"))
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if want[n] != got[n] {
			t.Errorf("%s differs from testdata/%s/after:\n--- got\n%s\n--- want\n%s", n, id, got[n], want[n])
		}
		delete(want, n)
	}
	for n := range want {
		t.Errorf("testdata/%s/after/%s was not produced", id, n)
	}
	if !res.Changed() {
		t.Error("the install reported no change")
	}

	// A second install leaves every file as the first one wrote it.
	again, err := Install(d, opts)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if again.Changed() {
		t.Errorf("the second install changed files: %+v", again.Changes)
	}
	if after := readTree(t, home); len(after) != len(got)+countBackups(after) {
		t.Errorf("the second install changed the file set")
	}
}

func countBackups(tree map[string]string) int {
	n := 0
	for name := range tree {
		if strings.HasSuffix(name, merge.BackupSuffix) {
			n++
		}
	}
	return n
}

func TestCodexInstallGolden(t *testing.T)    { installGolden(t, "codex", Parts{}) }
func TestCursorInstallGolden(t *testing.T)   { installGolden(t, "cursor", Parts{}) }
func TestGeminiInstallGolden(t *testing.T)   { installGolden(t, "gemini-cli", Parts{}) }
func TestOpenCodeInstallGolden(t *testing.T) { installGolden(t, "opencode", Parts{}) }
func TestCopilotInstallGolden(t *testing.T)  { installGolden(t, "copilot-cli", Parts{}) }
func TestAntigravityInstallGolden(t *testing.T) {
	installGolden(t, "antigravity", Parts{})
}
func TestWindsurfInstallGolden(t *testing.T) { installGolden(t, "windsurf", Parts{}) }

// Claude Code's hook is installed by the guard package; the MCP server and
// rules block come from here.
func TestClaudeCodeInstallGolden(t *testing.T) {
	installGolden(t, "claude-code", Parts{MCP: true, Rules: true})
}

func TestUninstallRemovesOnlyKeylatch(t *testing.T) {
	for _, d := range harness.Installable() {
		t.Run(d.ID, func(t *testing.T) {
			home := t.TempDir()
			copyTree(t, filepath.Join("testdata", d.ID, "before"), home)
			parts := Parts{}
			if d.ID == "claude-code" {
				parts = Parts{MCP: true, Rules: true}
			}
			original := readTree(t, home)
			opts := Options{
				Env: testEnv(home), Command: GuardCommand(d, testBinary), Binary: testBinary,
				Server: Server{Command: testBinary}, Parts: parts,
			}
			if _, err := Install(d, opts); err != nil {
				t.Fatal(err)
			}
			res, err := Uninstall(d, opts)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Changed() {
				t.Error("uninstall removed nothing")
			}
			for name, content := range readTree(t, home) {
				if strings.HasSuffix(name, merge.BackupSuffix) || strings.HasPrefix(name, ".gemini/settings.json") && d.ID == "antigravity" {
					continue
				}
				if strings.Contains(content, "guard hook --harness") || strings.Contains(content, merge.MarkdownBegin) || strings.Contains(content, merge.BlockBegin) {
					t.Errorf("%s still holds Keylatch after uninstall:\n%s", name, content)
				}
				if strings.Contains(content, `"keylatch"`) && strings.Contains(content, "mcp") && strings.Contains(content, "--stdio") {
					t.Errorf("%s still registers the MCP server", name)
				}
			}
			// What the user wrote survives: every user string in the originals
			// is still in the file it came from.
			for name, content := range original {
				now, err := os.ReadFile(filepath.Join(home, filepath.FromSlash(name)))
				if err != nil {
					continue
				}
				for _, line := range userMarkers(content) {
					if !strings.Contains(lf(now), line) {
						t.Errorf("%s lost %q", name, line)
					}
				}
			}
		})
	}
}

// userMarkers picks the strings fixtures use to mark the user's own content.
func userMarkers(content string) []string {
	var out []string
	for _, m := range []string{"my-audit", "my-rules", "user-hook", "other-server", "my codex settings"} {
		if strings.Contains(content, m) {
			out = append(out, m)
		}
	}
	return out
}

func TestUpgradeRewritesTheCommand(t *testing.T) {
	d, _ := harness.Lookup("gemini-cli")
	home := t.TempDir()
	env := testEnv(home)
	old := Options{Env: env, Command: GuardCommand(d, "/old/keylatch"), Parts: Parts{Guard: true}}
	if _, err := Install(d, old); err != nil {
		t.Fatal(err)
	}
	fresh := Options{Env: env, Command: GuardCommand(d, "/new/keylatch"), Parts: Parts{Guard: true}}
	res, err := Install(d, fresh)
	if err != nil || res.Changed() {
		t.Fatalf("without --upgrade the installed entry stays: %v changed=%v", err, res.Changed())
	}
	fresh.Upgrade = true
	if res, err = Install(d, fresh); err != nil || !res.Changed() {
		t.Fatalf("--upgrade rewrites it: %v changed=%v", err, res.Changed())
	}
	st := Inspect(d, env)
	if !st.Hook.Present || st.GuardBinary != "/new/keylatch" {
		t.Fatalf("status after upgrade: %+v", st)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	d, _ := harness.Lookup("codex")
	home := t.TempDir()
	res, err := Install(d, Options{Env: testEnv(home), Command: GuardCommand(d, testBinary), Server: Server{Command: testBinary}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed() {
		t.Fatal("a dry run still reports the change")
	}
	if len(readTree(t, home)) != 0 {
		t.Fatal("a dry run wrote files")
	}
}

func TestInstallRefusesWhatItCannotMerge(t *testing.T) {
	d, _ := harness.Lookup("gemini-cli")
	home := t.TempDir()
	path := filepath.Join(home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const withComment = "{\n// my theme\n\"theme\": \"dark\"}\n"
	if err := os.WriteFile(path, []byte(withComment), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Install(d, Options{Env: testEnv(home), Command: GuardCommand(d, testBinary), Parts: Parts{Guard: true}})
	if err == nil || !strings.Contains(err.Error(), "settings.json") {
		t.Fatalf("a settings file with comments must be refused, got %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != withComment {
		t.Fatal("the refused file was modified")
	}
	if _, err := Install(d, Options{Env: testEnv(home), Parts: Parts{Guard: true}}); err == nil {
		t.Fatal("a guard install without a command must fail")
	}
}

func TestLaunchOnlyAndUnknownHarnessesAreNotInstallable(t *testing.T) {
	d, _ := harness.Lookup("aider")
	if _, err := Install(d, Options{}); err == nil {
		t.Fatal("aider has nothing to install")
	}
	if _, err := Uninstall(d, Options{}); err == nil {
		t.Fatal("aider has nothing to uninstall")
	}
}

func TestProjectScope(t *testing.T) {
	d, _ := harness.Lookup("cursor")
	proj := t.TempDir()
	e := Env{Home: t.TempDir(), Project: proj, Getenv: func(string) string { return "" }}
	res, err := Install(d, Options{Env: e, Command: GuardCommand(d, testBinary), Server: Server{Command: testBinary}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 {
		t.Error("the user-level-only MCP registration is not mentioned")
	}
	tree := readTree(t, proj)
	if _, ok := tree[".cursor/hooks.json"]; !ok {
		t.Errorf("project hook missing: %v", tree)
	}
	mdc := tree[".cursor/rules/keylatch.mdc"]
	if !strings.HasPrefix(mdc, "---\n") || !strings.Contains(mdc, merge.MarkdownBegin) {
		t.Errorf("project rules file: %q", mdc)
	}
	if runtime.GOOS != "windows" {
		if st := Inspect(d, e); !st.Hook.Present || !st.Rules.Present {
			t.Errorf("status: %+v", st)
		}
	}
}

func TestInspectReportsDamage(t *testing.T) {
	d, _ := harness.Lookup("codex")
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := Inspect(d, testEnv(home))
	if !st.Detected || st.Hook.Err == nil || st.Hook.Present {
		t.Fatalf("status: %+v", st)
	}
	if st := Inspect(d, testEnv(t.TempDir())); st.Detected || st.Hook.Present || st.MCP.Present {
		t.Fatalf("nothing installed: %+v", st)
	}
}

func TestBinaryOf(t *testing.T) {
	for in, want := range map[string]string{
		`"/opt/keylatch/bin/keylatch" guard hook --harness codex`: "/opt/keylatch/bin/keylatch",
		`"C:/Program Files/k.exe" guard hook`:                     "C:/Program Files/k.exe",
		`"/a \"b\"/k" x`:                                          `/a "b"/k`,
		`/bare/keylatch guard hook`:                               "",
		`"unterminated`:                                           "",
	} {
		if got := binaryOf(in); got != want {
			t.Errorf("binaryOf(%q) = %q, want %q", in, got, want)
		}
	}
}
