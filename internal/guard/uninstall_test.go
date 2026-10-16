package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallRemovesWhatInstallWrote(t *testing.T) {
	for _, agent := range []Agent{AgentClaudeCode, AgentCursor, AgentCodex, AgentGemini, AgentCopilot, AgentAntigravity, AgentOpenCode} {
		t.Run(string(agent), func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)

			if _, err := Install(agent, InstallOpts{}); err != nil {
				t.Fatal(err)
			}
			path, removed, err := Uninstall(agent, InstallOpts{})
			if err != nil || !removed {
				t.Fatalf("Uninstall = %v, %v", removed, err)
			}
			if _, err := os.Stat(filepath.Join(home, ".keylatch", "hooks", scriptName(agent))); err == nil {
				t.Fatalf("%s guard script left behind", agent)
			}
			if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), scriptName(agent)) {
				t.Fatalf("%s still references its guard script: %s", path, data)
			}

			_, removed, err = Uninstall(agent, InstallOpts{})
			if err != nil || removed {
				t.Fatalf("second Uninstall = %v, %v; want a quiet no-op", removed, err)
			}
		})
	}
}

func TestUninstallKeepsOtherHooks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	other := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/local/bin/other-hook"}]}]},"theme":"dark"}`
	if err := os.WriteFile(settings, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(AgentClaudeCode, InstallOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Uninstall(AgentClaudeCode, InstallOpts{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "other-hook") || !strings.Contains(string(got), `"theme"`) || strings.Contains(string(got), "block-keylatch-exfiltration") {
		t.Fatalf("settings after uninstall: %s", got)
	}
}

func TestUninstallUnsupportedAgent(t *testing.T) {
	if _, _, err := Uninstall(Agent("no-such-agent"), InstallOpts{}); err == nil {
		t.Fatal("expected an error for an agent with no guard")
	}
}

func TestUninstallKeepsScriptWhileAnotherAgentUsesIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, a := range []Agent{AgentCursor, AgentCodex} {
		if _, err := Install(a, InstallOpts{}); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(home, ".keylatch", "hooks", scriptName(AgentCursor))
	if _, removed, err := Uninstall(AgentCursor, InstallOpts{}); err != nil || !removed {
		t.Fatalf("Uninstall cursor = %v, %v", removed, err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("shared script removed while codex still runs it: %v", err)
	}
	if _, _, err := Uninstall(AgentCodex, InstallOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err == nil {
		t.Fatal("script left behind after the last agent was uninstalled")
	}
}
