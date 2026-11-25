package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCCAgentSetup_ClaudeCodeWritesSettings(t *testing.T) {
	ccEnv(t)
	home := os.Getenv("HOME")
	settings := filepath.Join(home, ".claude", "settings.json")

	diffOut, _, err := ccRun(t, "", "agent", "setup", "claude-code", "--diff")
	if err != nil {
		t.Fatalf("agent setup --diff: %v", err)
	}
	if !strings.Contains(diffOut, "[NEW]") {
		t.Fatalf("diff before setup should announce new files: %q", diffOut)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatalf("--diff must not write files (stat err %v)", err)
	}

	dryOut, _, err := ccRun(t, "", "agent", "setup", "claude-code", "--dry-run")
	if err != nil {
		t.Fatalf("agent setup --dry-run: %v", err)
	}
	if strings.Contains(dryOut, "Written:") {
		t.Fatalf("--dry-run reported writes: %q", dryOut)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatalf("--dry-run must not write files (stat err %v)", err)
	}

	out, _, err := ccRun(t, "", "agent", "setup", "claude-code", "--mode", "")
	if err != nil {
		t.Fatalf("agent setup: %v", err)
	}
	if !strings.Contains(out, "Written: ") {
		t.Fatalf("setup output = %q", out)
	}
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("settings.json invalid: %v", err)
	}
	if !strings.Contains(string(data), "keylatch") {
		t.Fatalf("settings.json lacks keylatch entry: %s", data)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(settings); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("settings.json mode = %v, %v", info.Mode().Perm(), err)
		}
	}

	again, _, err := ccRun(t, "", "agent", "setup", "claude-code", "--diff")
	if err != nil {
		t.Fatalf("agent setup --diff after setup: %v", err)
	}
	if strings.Contains(again, "[NEW]") {
		t.Fatalf("diff after setup still reports new files: %q", again)
	}
}

func TestCCAgentSnippet_Formats(t *testing.T) {
	ccEnv(t)

	prose, _, err := ccRun(t, "", "agent", "snippet")
	if err != nil {
		t.Fatalf("snippet: %v", err)
	}
	if strings.TrimSpace(prose) == "" || !strings.Contains(strings.ToLower(prose), "keylatch") {
		t.Fatalf("prose snippet = %q", prose)
	}

	mcpOut, _, err := ccRun(t, "", "agent", "snippet", "--format", "mcp-json")
	if err != nil {
		t.Fatalf("snippet mcp-json: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(mcpOut), &cfg); err != nil {
		t.Fatalf("mcp-json is not JSON: %v (%q)", err, mcpOut)
	}

	both, _, err := ccRun(t, "", "agent", "snippet", "--format", "both")
	if err != nil {
		t.Fatalf("snippet both: %v", err)
	}
	parts := strings.SplitN(both, "\n---\n", 2)
	if len(parts) != 2 || parts[0] != prose {
		t.Fatalf("both should be prose, separator, then mcp json: %q", both)
	}
	if err := json.Unmarshal([]byte(parts[1]), &cfg); err != nil {
		t.Fatalf("both: trailing part is not JSON: %v", err)
	}
}
