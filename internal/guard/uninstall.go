package guard

import (
	"fmt"
	"os"
	"path/filepath"
)

// Uninstall removes the guard hook for agent. The shared guard script goes too
// unless another agent's configuration still runs it. It returns the
// configuration file it edited and whether anything was removed. A guard that
// is not installed is not an error.
func Uninstall(agent Agent, opts InstallOpts) (settingsPath string, removed bool, err error) {
	if agent == AgentOpenCode {
		return uninstallOpenCode()
	}
	switch agent {
	case AgentClaudeCode:
		settingsPath, err = resolveSettingsPath(opts)
	case AgentCursor, AgentCodex, AgentCopilot, AgentGemini, AgentAntigravity:
		var home string
		if home, err = os.UserHomeDir(); err != nil {
			return "", false, fmt.Errorf("install-guard: cannot determine home directory: %w", err)
		}
		settingsPath = harnessConfigPath(agent, home)
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
	command := hookCommand(agent, scriptPath)
	settings, err := loadSettings(settingsPath)
	if err != nil {
		return "", false, err
	}
	_, removed = pruneHooks(settings, func(cmd string) bool { return cmd == command })
	if agent == AgentAntigravity {
		if _, ok := settings["keylatch-guard"]; ok {
			delete(settings, "keylatch-guard")
			removed = true
		}
	}
	if removed {
		if err := saveSettings(settingsPath, settings); err != nil {
			return "", false, err
		}
	}
	if scriptInUse(agent, opts) {
		return settingsPath, removed, nil
	}
	if err := os.Remove(scriptPath); err == nil {
		removed = true
	} else if !os.IsNotExist(err) {
		return settingsPath, removed, fmt.Errorf("install-guard: remove %q: %w", scriptPath, err)
	}
	return settingsPath, removed, nil
}

// scriptInUse reports whether a configuration other than agent's still runs the
// shared guard script. A configuration that cannot be read counts as in use so
// the script is never pulled out from under a working hook.
func scriptInUse(agent Agent, opts InstallOpts) bool {
	if opts.ProjectDir != "" {
		return false
	}
	for _, other := range SupportedAgents {
		if other == agent || other == AgentOpenCode {
			continue
		}
		if installed, err := IsInstalled(other, opts); installed || err != nil {
			return true
		}
	}
	return false
}

func homeJoin(elem ...string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	return filepath.Join(append([]string{home}, elem...)...), nil
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
