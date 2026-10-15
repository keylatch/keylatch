package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Uninstall removes the guard hook for agent and the script Install wrote. It
// returns the settings file it edited and whether anything was removed. A
// guard that is not installed is not an error.
func Uninstall(agent Agent, opts InstallOpts) (settingsPath string, removed bool, err error) {
	switch agent {
	case AgentClaudeCode:
		settingsPath, err = resolveSettingsPath(opts)
	case AgentCursor:
		settingsPath, err = homeJoin(".cursor", "settings.json")
	case AgentCodex:
		settingsPath, err = homeJoin(".codex", "hooks.json")
	case AgentGemini:
		settingsPath, err = geminiSettingsPath()
	case AgentAider:
		return uninstallAider(opts)
	case AgentOpenCode:
		return uninstallOpenCode()
	default:
		return "", false, fmt.Errorf("install-guard: --uninstall is not supported for %q; remove its guard by hand", agent)
	}
	if err != nil {
		return "", false, err
	}
	scriptPath, err := guardScriptPath(agent, opts)
	if err != nil {
		return "", false, err
	}
	settings, err := loadSettings(settingsPath)
	if err != nil {
		return "", false, err
	}
	removed = removeHookEntries(settings, scriptPath)
	if removed {
		if err := saveSettings(settingsPath, settings); err != nil {
			return "", false, err
		}
	}
	if err := os.Remove(scriptPath); err == nil {
		removed = true
	} else if !os.IsNotExist(err) {
		return settingsPath, removed, fmt.Errorf("install-guard: remove %q: %w", scriptPath, err)
	}
	return settingsPath, removed, nil
}

func homeJoin(elem ...string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	return filepath.Join(append([]string{home}, elem...)...), nil
}

func geminiSettingsPath() (string, error) {
	p, err := homeJoin(".gemini", "settings.json")
	if err != nil {
		return "", err
	}
	if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
		alt, _ := homeJoin(".config", "gemini", "settings.json")
		if _, altErr := os.Stat(alt); altErr == nil {
			return alt, nil
		}
	}
	return p, nil
}

// removeHookEntries deletes every hook command equal to scriptPath from the
// array-style and object-style "hooks" layouts, and drops matcher groups that
// end up empty. It reports whether anything changed.
func removeHookEntries(settings map[string]any, scriptPath string) bool {
	switch h := settings["hooks"].(type) {
	case []any:
		kept, changed := filterGroups(h, scriptPath)
		if changed {
			settings["hooks"] = kept
		}
		return changed
	case map[string]any:
		changed := false
		for event, raw := range h {
			groups, ok := raw.([]any)
			if !ok {
				continue
			}
			kept, c := filterGroups(groups, scriptPath)
			if !c {
				continue
			}
			changed = true
			if len(kept) == 0 {
				delete(h, event)
			} else {
				h[event] = kept
			}
		}
		return changed
	}
	return false
}

func filterGroups(groups []any, scriptPath string) (kept []any, changed bool) {
	kept = make([]any, 0, len(groups))
	for _, raw := range groups {
		entry, ok := raw.(map[string]any)
		if !ok {
			kept = append(kept, raw)
			continue
		}
		if cmd, _ := entry["command"].(string); cmd == scriptPath {
			changed = true
			continue
		}
		inner, ok := entry["hooks"].([]any)
		if !ok {
			kept = append(kept, raw)
			continue
		}
		left := make([]any, 0, len(inner))
		for _, h := range inner {
			if hm, ok := h.(map[string]any); ok {
				if cmd, _ := hm["command"].(string); cmd == scriptPath {
					changed = true
					continue
				}
			}
			left = append(left, h)
		}
		if len(left) == 0 {
			continue
		}
		entry["hooks"] = left
		kept = append(kept, entry)
	}
	return kept, changed
}

func uninstallAider(opts InstallOpts) (string, bool, error) {
	confPath, err := homeJoin(".aider.conf.yml")
	if err != nil {
		return "", false, err
	}
	scriptPath, err := guardScriptPath(AgentAider, opts)
	if err != nil {
		return "", false, err
	}
	data, err := os.ReadFile(confPath)
	if os.IsNotExist(err) {
		return confPath, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("install-guard: read aider config: %w", err)
	}
	var kept []string
	removed := false
	for _, line := range splitLines(string(data)) {
		if strings.Contains(line, "pre-tool-use-hook") && strings.Contains(line, scriptPath) {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if removed {
		if err := os.WriteFile(confPath, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
			return "", false, fmt.Errorf("install-guard: write aider config: %w", err)
		}
	}
	if err := os.Remove(scriptPath); err == nil {
		removed = true
	}
	return confPath, removed, nil
}

func uninstallOpenCode() (string, bool, error) {
	pluginDir, err := homeJoin(".config", "opencode", "plugins", "keylatch-guard")
	if err != nil {
		return "", false, err
	}
	configPath, err := homeJoin(".config", "opencode", "opencode.json")
	if err != nil {
		return "", false, err
	}
	removed := false
	if _, err := os.Stat(pluginDir); err == nil {
		if err := os.RemoveAll(pluginDir); err != nil {
			return "", false, fmt.Errorf("install-guard: remove %q: %w", pluginDir, err)
		}
		removed = true
	}
	settings, err := loadSettings(configPath)
	if err != nil {
		return "", removed, err
	}
	plugins, _ := settings["plugins"].([]any)
	pluginPath := filepath.Join(pluginDir, "index.ts")
	kept := make([]any, 0, len(plugins))
	for _, p := range plugins {
		if s, ok := p.(string); ok && s == pluginPath {
			removed = true
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) != len(plugins) {
		settings["plugins"] = kept
		if err := saveSettings(configPath, settings); err != nil {
			return "", removed, err
		}
	}
	return configPath, removed, nil
}
