package installer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/harness"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func install(t *testing.T, id, home string, parts Parts) (harness.Descriptor, Options) {
	t.Helper()
	d, ok := harness.Lookup(id)
	if !ok {
		t.Fatalf("no harness %q", id)
	}
	o := Options{
		Env: testEnv(home), Command: GuardCommand(d, testBinary), Binary: testBinary,
		Server: Server{Command: testBinary}, Parts: parts,
	}
	if _, err := Install(d, o); err != nil {
		t.Fatalf("install %s: %v", id, err)
	}
	return d, o
}

func TestInspectEveryHarnessAfterInstall(t *testing.T) {
	for _, d := range harness.Installable() {
		t.Run(d.ID, func(t *testing.T) {
			home := t.TempDir()
			parts := Parts{}
			if d.ID == "claude-code" {
				parts = Parts{MCP: true, Rules: true}
			}
			install(t, d.ID, home, parts)
			st := Inspect(d, testEnv(home))
			if !st.Detected || !st.MCP.Present || st.MCP.Err != nil {
				t.Fatalf("MCP: %+v", st)
			}
			if d.Rules.File != "" && !st.Rules.Present {
				t.Errorf("rules block not seen: %+v", st.Rules)
			}
			if d.ID == "claude-code" {
				return
			}
			if !st.Hook.Present || st.Hook.Err != nil {
				t.Fatalf("hook: %+v", st.Hook)
			}
			if st.GuardBinary != testBinary {
				t.Errorf("GuardBinary = %q, want %q", st.GuardBinary, testBinary)
			}
		})
	}
}

func TestInspectSeesClaudeCodeHookWrittenByTheGuardPackage(t *testing.T) {
	d, _ := harness.Lookup("claude-code")
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude", "settings.json"),
		`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"\"/opt/k/keylatch\" guard hook --harness claude-code"}]}]}}`)
	st := Inspect(d, testEnv(home))
	if !st.Hook.Present || st.GuardBinary != "/opt/k/keylatch" {
		t.Fatalf("status: %+v", st)
	}
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{}}`)
	if st := Inspect(d, testEnv(home)); st.Hook.Present {
		t.Fatalf("no hook installed: %+v", st)
	}
}

func TestInspectMCPEdgeCases(t *testing.T) {
	d, _ := harness.Lookup("cursor")
	home := t.TempDir()
	mcp := filepath.Join(home, ".cursor", "mcp.json")
	for name, content := range map[string]string{"servers is a string": `{"mcpServers":"x"}`, "no servers": `{}`, "other server": `{"mcpServers":{"a":{}}}`} {
		write(t, mcp, content)
		if st := Inspect(d, testEnv(home)); st.MCP.Present || st.MCP.Err != nil {
			t.Errorf("%s: %+v", name, st.MCP)
		}
	}
	write(t, mcp, `{`)
	if st := Inspect(d, testEnv(home)); st.MCP.Err == nil {
		t.Error("damaged JSON must be reported")
	}
}

func TestOpenCodePluginLifecycle(t *testing.T) {
	home := t.TempDir()
	d, o := install(t, "opencode", home, Parts{Guard: true})
	plugin := filepath.Join(home, ".config", "opencode", "plugins", "keylatch-guard.ts")

	o.Command, o.Binary = GuardCommand(d, "/new/keylatch"), "/new/keylatch"
	if res, err := Install(d, o); err != nil || res.Changed() {
		t.Fatalf("without --upgrade an installed plugin stays: %v %v", err, res.Changes)
	}
	o.Upgrade = true
	if res, err := Install(d, o); err != nil || !res.Changed() {
		t.Fatalf("--upgrade rewrites it: %v %v", err, res.Changes)
	}
	if st := Inspect(d, testEnv(home)); st.GuardBinary != "/new/keylatch" {
		t.Fatalf("status: %+v", st)
	}

	o.DryRun, o.Upgrade = true, false
	res, err := Uninstall(d, o)
	if err != nil || !res.Changed() {
		t.Fatalf("dry-run uninstall: %v %v", err, res.Changes)
	}
	if _, err := os.Stat(plugin); err != nil {
		t.Fatal("a dry run removed the plugin")
	}
	o.DryRun = false
	if res, err = Uninstall(d, o); err != nil || !res.Changed() {
		t.Fatalf("uninstall: %v %v", err, res.Changes)
	}
	if _, err := os.Stat(plugin); !os.IsNotExist(err) {
		t.Fatal("the plugin is still there")
	}
	if res, err = Uninstall(d, o); err != nil || res.Changed() {
		t.Fatalf("uninstalling twice is a no-op: %v %v", err, res.Changes)
	}

	write(t, plugin, "// the user's own plugin\n")
	if res, err = Uninstall(d, o); err != nil || res.Changed() {
		t.Fatalf("a plugin that is not ours stays: %v %v", err, res.Changes)
	}
}

func TestLegacyArrayHooksAreMigrated(t *testing.T) {
	d, _ := harness.Lookup("codex")
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "hooks.json"), `{"hooks":[
 {"event":"PreToolUse","matcher":"Bash","hooks":[{"type":"command","command":"/usr/bin/audit"}]},
 {"matcher":"no event"},
 "stray"
]}`)
	install(t, "codex", home, Parts{Guard: true})
	data, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	s := string(data)
	for _, want := range []string{`"PreToolUse"`, "/usr/bin/audit", `"hooksLegacy"`, "no event", "stray", "guard hook --harness codex"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, `"event"`) {
		t.Errorf("the event key should have become the object key:\n%s", s)
	}
	if st := Inspect(d, testEnv(home)); !st.Hook.Present {
		t.Fatalf("status: %+v", st)
	}
}

func TestCodexMCPBlockIsUpgradedInPlace(t *testing.T) {
	d, _ := harness.Lookup("codex")
	home := t.TempDir()
	install(t, "codex", home, Parts{MCP: true})
	o := Options{Env: testEnv(home), Server: Server{Command: "/new/keylatch", Args: []string{"mcp", "--stdio", "--quiet"}}, Parts: Parts{MCP: true}}
	if _, err := Install(d, o); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	s := string(data)
	if !strings.Contains(s, `"/new/keylatch"`) || strings.Count(s, "[mcp_servers.keylatch]") != 1 || !strings.Contains(s, `"--quiet"`) {
		t.Fatalf("config.toml:\n%s", s)
	}
	if res, err := Uninstall(d, Options{Env: testEnv(home), Parts: Parts{MCP: true}}); err != nil || !res.Changed() {
		t.Fatalf("uninstall: %v %v", err, res.Changes)
	}
	if data, _ = os.ReadFile(filepath.Join(home, ".codex", "config.toml")); strings.Contains(string(data), "keylatch") {
		t.Fatalf("the block is still in:\n%s", data)
	}
}

func TestMCPAndRulesRefuseUnusableInput(t *testing.T) {
	d, _ := harness.Lookup("cursor")
	home := t.TempDir()
	if _, err := Install(d, Options{Env: testEnv(home), Parts: Parts{MCP: true}}); err == nil {
		t.Error("an MCP install without a server command must fail")
	}
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":[]}`)
	if _, err := Install(d, Options{Env: testEnv(home), Server: Server{Command: testBinary}, Parts: Parts{MCP: true}}); err == nil {
		t.Error("mcpServers that is not an object must not be overwritten")
	}
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{"keylatch":{"command":"custom"}}}`)
	res, err := Install(d, Options{Env: testEnv(home), Server: Server{Command: testBinary}, Parts: Parts{MCP: true}})
	if err != nil || res.Changed() {
		t.Errorf("a server entry the user wrote stays without --upgrade: %v %v", err, res.Changes)
	}
	proj := t.TempDir()
	write(t, filepath.Join(proj, ".cursor", "rules", "keylatch.mdc"), "<!-- keylatch:begin -->\nx\n")
	if _, err := Install(d, Options{Env: Env{Project: proj, Getenv: func(string) string { return "" }}, Parts: Parts{Rules: true}}); err == nil {
		t.Error("an unterminated Keylatch block must be refused")
	}
}

func TestProjectScopeNotesWhatItCannotDo(t *testing.T) {
	d, _ := harness.Lookup("opencode")
	res, err := Install(d, Options{Env: Env{Project: t.TempDir(), Getenv: func(string) string { return "" }}, Command: "x guard hook --harness opencode", Binary: testBinary, Server: Server{Command: testBinary}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 {
		t.Error("the MCP registration is user-level only and should say so")
	}
	cd, _ := harness.Lookup("codex")
	res, err = Install(cd, Options{Env: Env{Project: t.TempDir(), Getenv: func(string) string { return "" }}, Command: "x", Parts: Parts{Guard: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) < 2 {
		t.Errorf("Codex has no project hook file and needs a /hooks review: %v", res.Notes)
	}
}
