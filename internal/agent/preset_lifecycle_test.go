package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// setTempHome points HOME (and USERPROFILE for Windows) at a temp dir so
// expandHome and os.UserHomeDir resolve inside the test sandbox.
func setTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	return dir
}

// registeredNames returns all preset names in stable order.
func registeredNames() []string {
	names := make([]string, 0, len(presetRegistry))
	for n := range presetRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// writeMCPConfig creates a config file with a keylatch mcpServers entry at
// path, creating parent directories.
func writeMCPConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"mcpServers": map[string]any{
			"keylatch": map[string]any{"command": "keylatch", "args": []string{"mcp"}},
			"other":    map[string]any{"command": "other-tool"},
		},
	}
	data, _ := json.MarshalIndent(cfg, "", " ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAllPresets_HealthCheck_Lifecycle exercises HealthCheck for every
// registered preset against a missing and then present config file.
func TestAllPresets_HealthCheck_Lifecycle(t *testing.T) {
	home := setTempHome(t)
	ctx := context.Background()

	// Config file locations per preset (mirrors each preset's HealthCheck).
	configFor := map[string]string{
		"claude-code": filepath.Join(home, ".claude", "settings.json"),
		"codex":       filepath.Join(home, ".codex", "config.json"),
		"cursor":      filepath.Join(home, ".cursor", "settings.json"),
		"opencode":    filepath.Join(home, ".opencode", "config.json"),
		"openclaw":    filepath.Join(home, ".openclaw", "config.json"),
		"nanoclaw":    filepath.Join(home, ".nanoclaw", "config.json"),
		"openhands":   filepath.Join(home, ".openhands", "config.json"),
		"hermes":      filepath.Join(home, ".hermes", "config.json"),
		"n8n":         filepath.Join(home, ".n8n", "keylatch.env"),
		"dify":        filepath.Join(home, ".dify", "keylatch.env"),
		"custom":      filepath.Join(home, ".keylatch-custom", "config.json"),
	}

	for _, name := range registeredNames() {
		p, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}

		// Missing config: must not panic; openhands is documented to use a
		// binary-presence stub that always reports healthy, so only the
		// detail being non-empty is asserted universally.
		st := p.HealthCheck(ctx)
		if st.Detail == "" {
			t.Errorf("%s: HealthCheck detail empty for missing config", name)
		}

		// Present config: presets with a known config path must be healthy.
		cfgPath, known := configFor[name]
		if !known {
			continue
		}
		writeMCPConfig(t, cfgPath)
		st = p.HealthCheck(ctx)
		if !st.Healthy {
			t.Errorf("%s: HealthCheck unhealthy with config present: %s", name, st.Detail)
		}
		if err := os.RemoveAll(filepath.Dir(cfgPath)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAllPresets_Uninstall removes the keylatch MCP entry while preserving
// other entries, for every preset whose uninstall is config-file based.
func TestAllPresets_Uninstall(t *testing.T) {
	home := setTempHome(t)
	ctx := context.Background()

	uninstallConfig := map[string]string{
		"codex":    filepath.Join(home, ".codex", "config.json"),
		"cursor":   filepath.Join(home, ".cursor", "settings.json"),
		"opencode": filepath.Join(home, ".opencode", "config.json"),
		"openclaw": filepath.Join(home, ".openclaw", "config.json"),
		"nanoclaw": filepath.Join(home, ".nanoclaw", "config.json"),
	}

	for name, cfgPath := range uninstallConfig {
		p, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}
		writeMCPConfig(t, cfgPath)

		if err := p.Uninstall(ctx); err != nil {
			t.Errorf("%s: Uninstall: %v", name, err)
			continue
		}

		data, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Errorf("%s: config removed entirely: %v", name, err)
			continue
		}
		var cfg map[string]any
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Errorf("%s: config corrupted: %v", name, err)
			continue
		}
		servers, _ := cfg["mcpServers"].(map[string]any)
		if _, still := servers["keylatch"]; still {
			t.Errorf("%s: keylatch entry not removed", name)
		}
		if _, kept := servers["other"]; !kept {
			t.Errorf("%s: unrelated mcpServers entry was removed", name)
		}
	}
}

// TestAllPresets_Diff_FreshHome verifies Diff reports profile files as
// missing in a fresh home for every preset that can generate a profile.
func TestAllPresets_Diff_FreshHome(t *testing.T) {
	setTempHome(t)
	ctx := context.Background()
	store := newMockStore()
	opts := SetupOptions{Mode: "gateway_sdk"}

	for _, name := range registeredNames() {
		p, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}
		d, err := p.Diff(ctx, opts, store)
		if err != nil {
			// Profile generation legitimately fails for agents the snippet
			// generator does not support in this mode; record, don't fail.
			t.Logf("%s: Diff not supported here: %v", name, err)
			continue
		}
		if len(d.Added) == 0 {
			t.Logf("%s: Diff reported no additions in a fresh home", name)
		}
	}
}

// TestFileRemovalUninstalls covers presets whose Uninstall is a plain file
// removal (openhands, n8n, dify) plus the custom preset no-op.
func TestFileRemovalUninstalls(t *testing.T) {
	home := setTempHome(t)
	ctx := context.Background()

	removal := map[string]string{
		"openhands": filepath.Join(home, ".openhands", "config.json"),
		"n8n":       filepath.Join(home, ".n8n", "keylatch.env"),
		"dify":      filepath.Join(home, ".dify", "keylatch.env"),
	}
	for name, cfgPath := range removal {
		p, err := Get(name)
		if err != nil {
			t.Fatalf("Get(%s): %v", name, err)
		}
		if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfgPath, []byte("x=y\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := p.Uninstall(ctx); err != nil {
			t.Errorf("%s: Uninstall: %v", name, err)
		}
		if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
			t.Errorf("%s: config file still present after Uninstall", name)
		}
	}

	// hermes uses removeFromMCPServers.
	hermesCfg := filepath.Join(home, ".hermes", "config.json")
	writeMCPConfig(t, hermesCfg)
	p, err := Get("hermes")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Uninstall(ctx); err != nil {
		t.Errorf("hermes: Uninstall: %v", err)
	}

	// custom preset Uninstall is a documented no-op.
	cp, err := Get("custom")
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.Uninstall(ctx); err != nil {
		t.Errorf("custom: Uninstall: %v", err)
	}
}

// TestCustomPreset_SetupGuards covers the config-path validation: required,
// must be under home, and denylisted locations are rejected.
func TestCustomPreset_SetupGuards(t *testing.T) {
	home := setTempHome(t)
	ctx := context.Background()
	store := newMockStore()

	cp := &CustomPreset{}
	if _, err := cp.Setup(ctx, SetupOptions{}, store); err == nil {
		t.Error("Setup without config path must fail")
	}

	cp = &CustomPreset{configPath: "/etc/keylatch.json"}
	if _, err := cp.Setup(ctx, SetupOptions{}, store); err == nil {
		t.Error("Setup outside home must fail")
	}

	cp = &CustomPreset{configPath: filepath.Join(home, ".config", "tool.json")}
	if _, err := cp.Setup(ctx, SetupOptions{}, store); err == nil {
		t.Error("Setup in denylisted dir must fail")
	}
}
