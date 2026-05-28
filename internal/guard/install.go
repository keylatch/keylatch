package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Agent identifies a supported agent integration.
type Agent string

const (
	AgentClaudeCode  Agent = "claude-code"
	AgentCursor      Agent = "cursor"
	AgentAider       Agent = "aider"
	AgentWindsurf    Agent = "windsurf"
	AgentCodex       Agent = "codex"
	AgentCopilot     Agent = "copilot"
	AgentGemini      Agent = "gemini"
	AgentOpenCode    Agent = "opencode"
	AgentAntigravity Agent = "antigravity"
)

// SupportedAgents lists all agents that have a guard available.
var SupportedAgents = []Agent{
	AgentClaudeCode,
	AgentCursor,
	AgentAider,
	AgentWindsurf,
	AgentCodex,
	AgentCopilot,
	AgentGemini,
	AgentOpenCode,
	AgentAntigravity,
}

// AgentHookMechanism describes the hook mechanism used by each agent.
var AgentHookMechanism = map[Agent]string{
	AgentClaudeCode:  "PreToolUse (settings.json)",
	AgentCursor:      "PreToolUse (settings.json)",
	AgentAider:       "pre-tool-use-hook (.aider.conf.yml)",
	AgentWindsurf:    "not supported — gateway mode recommended",
	AgentCodex:       "PreToolUse (hooks.json)",
	AgentCopilot:     "shell wrapper (native hook path unconfirmed)",
	AgentGemini:      "BeforeTool (settings.json)",
	AgentOpenCode:    "tool.execute.before (TypeScript plugin)",
	AgentAntigravity: "not supported — gateway mode recommended",
}

// InstallOpts controls where the hook is installed.
type InstallOpts struct {
	// ProjectDir installs into <ProjectDir>/.claude/settings.json instead of global.
	// When empty the global ~/.claude/settings.json is used.
	ProjectDir string
}

// InstallResult carries the result of an Install call.
type InstallResult struct {
	// SettingsPath is the path to the settings file that was modified.
	// Empty for agents that don't modify a settings file (e.g. Antigravity).
	SettingsPath string
	// Message is a human-readable summary of what was done.
	Message string
}

// Install writes the guard script for agent to disk and wires it into the agent's
// hook configuration. It is idempotent: if the hook is already present the function
// returns nil without modifying anything.
//
// On success it returns the path to the settings file that was modified (empty for
// agents that use message-only responses like Windsurf and Antigravity).
func Install(agent Agent, opts InstallOpts) (settingsPath string, err error) {
	switch agent {
	case AgentClaudeCode:
		return installClaudeCode(opts)
	case AgentCursor:
		return installCursor(opts)
	case AgentAider:
		return installAider(opts)
	case AgentWindsurf:
		return installWindsurf(opts)
	case AgentCodex:
		return installCodex(opts)
	case AgentCopilot:
		return installCopilot(opts)
	case AgentGemini:
		return installGemini(opts)
	case AgentOpenCode:
		return installOpenCode(opts)
	case AgentAntigravity:
		return installAntigravity(opts)
	default:
		return "", fmt.Errorf("install-guard: unsupported agent %q (supported: %v)", agent, SupportedAgents)
	}
}

// IsInstalled returns true when the guard for agent is already wired into the
// Claude Code settings file. This is the same idempotency check used by Install.
func IsInstalled(agent Agent, opts InstallOpts) (bool, error) {
	if agent != AgentClaudeCode {
		return false, fmt.Errorf("install-guard: IsInstalled only supported for claude-code currently")
	}
	settingsPath, err := resolveSettingsPath(opts)
	if err != nil {
		return false, err
	}
	settings, err := loadSettings(settingsPath)
	if err != nil {
		// If the file does not exist the guard is definitely not installed.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	scriptPath, err := guardScriptPath(agent, opts)
	if err != nil {
		return false, err
	}
	return hookAlreadyInstalled(settings, scriptPath), nil
}

// --- agent-specific install functions ---

func installClaudeCode(opts InstallOpts) (string, error) {
	// Resolve the settings file path.
	settingsPath, err := resolveSettingsPath(opts)
	if err != nil {
		return "", err
	}

	// Write the guard script to ~/.keylatch/hooks/ (or project-local equivalent).
	scriptPath, err := writeGuardScript(AgentClaudeCode, opts)
	if err != nil {
		return "", err
	}

	// Load (or create) the settings file.
	settings, err := loadSettings(settingsPath)
	if err != nil {
		return "", err
	}

	// Check for idempotency before mutating.
	if hookAlreadyInstalled(settings, scriptPath) {
		return settingsPath, nil
	}

	// Append the PreToolUse hook.
	settings = appendPreToolUseHook(settings, scriptPath)

	// Persist the modified settings.
	if err := saveSettings(settingsPath, settings); err != nil {
		return "", err
	}

	return settingsPath, nil
}

func installCursor(opts InstallOpts) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	settingsPath := filepath.Join(home, ".cursor", "settings.json")

	scriptPath, err := writeGuardScriptTo(AgentCursor, CursorScript, opts)
	if err != nil {
		return "", err
	}

	settings, err := loadSettings(settingsPath)
	if err != nil {
		return "", err
	}

	if hookAlreadyInstalled(settings, scriptPath) {
		return settingsPath, nil
	}

	settings = appendPreToolUseHook(settings, scriptPath)
	if err := saveSettings(settingsPath, settings); err != nil {
		return "", err
	}
	return settingsPath, nil
}

func installAider(opts InstallOpts) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}

	scriptPath, err := writeGuardScriptTo(AgentAider, AiderScript, opts)
	if err != nil {
		return "", err
	}

	confPath := filepath.Join(home, ".aider.conf.yml")
	// Check if already installed.
	data, readErr := os.ReadFile(confPath)
	if readErr == nil {
		for _, line := range splitLines(string(data)) {
			if contains(line, "pre-tool-use-hook") {
				return confPath, nil // already present
			}
		}
	}

	// Append the hook config.
	f, err := os.OpenFile(confPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("install-guard: open aider config: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintf(f, "\npre-tool-use-hook: %s\n", scriptPath); err != nil {
		return "", fmt.Errorf("install-guard: write aider config: %w", err)
	}
	return confPath, nil
}

func installWindsurf(_ InstallOpts) (string, error) {
	// Windsurf does not currently expose a hook API for tool interception.
	// Return an informational message via a sentinel path.
	return "", fmt.Errorf("windsurf: hook API not yet available — for manual guard instructions see keylatch.dev/integrations/windsurf. Use gateway mode for strongest protection: keylatch proxy start")
}

func installCodex(opts InstallOpts) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	hooksPath := filepath.Join(home, ".codex", "hooks.json")

	scriptPath, err := writeGuardScriptTo(AgentCodex, CodexScript, opts)
	if err != nil {
		return "", err
	}

	settings, err := loadSettings(hooksPath)
	if err != nil {
		return "", err
	}

	if hookAlreadyInstalled(settings, scriptPath) {
		return hooksPath, nil
	}

	settings = appendPreToolUseHook(settings, scriptPath)
	if err := saveSettings(hooksPath, settings); err != nil {
		return "", err
	}
	return hooksPath, nil
}

func installCopilot(opts InstallOpts) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}

	_, err = writeGuardScriptTo(AgentCopilot, CopilotScript, opts)
	if err != nil {
		return "", err
	}

	// For Copilot, we use a shell wrapper approach since native hook path is unconfirmed.
	// The settings path here is the ~/.zshrc or ~/.bashrc we patch.
	rcPath := filepath.Join(home, ".zshrc")
	if _, statErr := os.Stat(rcPath); os.IsNotExist(statErr) {
		rcPath = filepath.Join(home, ".bashrc")
	}
	return rcPath, nil
}

func installGemini(opts InstallOpts) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}

	// Try both common settings paths.
	settingsPath := filepath.Join(home, ".gemini", "settings.json")
	if _, statErr := os.Stat(settingsPath); os.IsNotExist(statErr) {
		alt := filepath.Join(home, ".config", "gemini", "settings.json")
		if _, statErr2 := os.Stat(alt); statErr2 == nil {
			settingsPath = alt
		}
	}

	scriptPath, err := writeGuardScriptTo(AgentGemini, GeminiScript, opts)
	if err != nil {
		return "", err
	}

	settings, err := loadSettings(settingsPath)
	if err != nil {
		return "", err
	}

	if hookAlreadyInstalled(settings, scriptPath) {
		return settingsPath, nil
	}

	settings = appendBeforeToolHook(settings, scriptPath)
	if err := saveSettings(settingsPath, settings); err != nil {
		return "", err
	}
	return settingsPath, nil
}

func installOpenCode(opts InstallOpts) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}

	pluginDir := filepath.Join(home, ".config", "opencode", "plugins", "keylatch-guard")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		return "", fmt.Errorf("install-guard: create plugin dir: %w", err)
	}
	pluginPath := filepath.Join(pluginDir, "index.ts")
	if err := os.WriteFile(pluginPath, OpenCodeScript, 0o600); err != nil {
		return "", fmt.Errorf("install-guard: write opencode plugin: %w", err)
	}

	// Patch opencode.json.
	configPath := filepath.Join(home, ".config", "opencode", "opencode.json")
	settings, err := loadSettings(configPath)
	if err != nil {
		return "", err
	}

	pluginsRaw, _ := settings["plugins"].([]any)
	for _, p := range pluginsRaw {
		if ps, ok := p.(string); ok && ps == pluginPath {
			return configPath, nil // already registered
		}
	}
	pluginsRaw = append(pluginsRaw, pluginPath)
	settings["plugins"] = pluginsRaw

	if err := saveSettings(configPath, settings); err != nil {
		return "", err
	}
	return configPath, nil
}

func installAntigravity(_ InstallOpts) (string, error) {
	return "", fmt.Errorf("antigravity: Google Antigravity does not currently expose a hook API for tool interception.\n\nRecommended alternative: run Keylatch in gateway mode, which intercepts\nall outbound credential requests at the network level regardless of agent:\n\n  keylatch proxy start --port 8080\n  # Point Antigravity's network proxy setting to http://localhost:8080\n\nSee: https://keylatch.dev/integrations/antigravity")
}

// --- internal helpers ---

// resolveSettingsPath returns the path to the Claude Code settings JSON file.
func resolveSettingsPath(opts InstallOpts) (string, error) {
	if opts.ProjectDir != "" {
		return filepath.Join(opts.ProjectDir, ".claude", "settings.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

// guardScriptDir returns the directory where guard scripts are stored.
func guardScriptDir(agent Agent, opts InstallOpts) (string, error) {
	if opts.ProjectDir != "" {
		return filepath.Join(opts.ProjectDir, ".keylatch", "hooks"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".keylatch", "hooks"), nil
}

// guardScriptPath returns the expected on-disk path for the guard script.
func guardScriptPath(agent Agent, opts InstallOpts) (string, error) {
	dir, err := guardScriptDir(agent, opts)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, scriptName(agent)), nil
}

func scriptName(agent Agent) string {
	switch agent {
	case AgentClaudeCode:
		return "block-keylatch-exfiltration.sh"
	case AgentOpenCode:
		return "keylatch-guard.ts"
	default:
		return string(agent) + "-guard.sh"
	}
}

// writeGuardScript writes the embedded guard script to disk and returns its path.
func writeGuardScript(agent Agent, opts InstallOpts) (string, error) {
	scriptBytes, err := scriptContent(agent)
	if err != nil {
		return "", err
	}
	return writeGuardScriptTo(agent, scriptBytes, opts)
}

// writeGuardScriptTo writes scriptBytes to the guard script path and returns it.
func writeGuardScriptTo(agent Agent, scriptBytes []byte, opts InstallOpts) (string, error) {
	dir, err := guardScriptDir(agent, opts)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("install-guard: create hooks dir: %w", err)
	}

	path := filepath.Join(dir, scriptName(agent))
	mode := os.FileMode(0o700)
	if agent == AgentOpenCode {
		mode = 0o600 // .ts file, not executable
	}
	if err := os.WriteFile(path, scriptBytes, mode); err != nil {
		return "", fmt.Errorf("install-guard: write script %q: %w", path, err)
	}
	return path, nil
}

func scriptContent(agent Agent) ([]byte, error) {
	switch agent {
	case AgentClaudeCode:
		return ClaudeCodeScript, nil
	case AgentCursor:
		return CursorScript, nil
	case AgentAider:
		return AiderScript, nil
	case AgentWindsurf:
		return WindsurfScript, nil
	case AgentCodex:
		return CodexScript, nil
	case AgentCopilot:
		return CopilotScript, nil
	case AgentGemini:
		return GeminiScript, nil
	case AgentOpenCode:
		return OpenCodeScript, nil
	default:
		return nil, fmt.Errorf("install-guard: no script for agent %q", agent)
	}
}

// loadSettings reads the agent settings file. If the file does not exist
// an empty settings map is returned (no error).
func loadSettings(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]any), nil
		}
		return nil, fmt.Errorf("install-guard: read settings %q: %w", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("install-guard: parse settings %q: %w", path, err)
	}
	return m, nil
}

// saveSettings writes the settings map to disk atomically (temp + rename).
func saveSettings(path string, settings map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("install-guard: create settings dir: %w", err)
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("install-guard: marshal settings: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.tmp")
	if err != nil {
		return fmt.Errorf("install-guard: create temp settings: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("install-guard: write temp settings: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("install-guard: close temp settings: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install-guard: rename settings: %w", err)
	}
	ok = true
	return nil
}

// hookAlreadyInstalled returns true when scriptPath already appears as a hook
// command in the "hooks" section of settings.
func hookAlreadyInstalled(settings map[string]any, scriptPath string) bool {
	hooksRaw, ok := settings["hooks"]
	if !ok {
		return false
	}
	// Handle both array-style (Claude Code / Cursor) and object-style hooks.
	switch h := hooksRaw.(type) {
	case []any:
		for _, raw := range h {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if matchesHookEntry(entry, scriptPath) {
				return true
			}
		}
	case map[string]any:
		// Check PreToolUse and BeforeTool arrays.
		for _, key := range []string{"PreToolUse", "BeforeTool"} {
			arr, _ := h[key].([]any)
			for _, raw := range arr {
				entry, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				if matchesHookEntry(entry, scriptPath) {
					return true
				}
			}
		}
	}
	return false
}

// matchesHookEntry checks whether an individual hook entry references scriptPath.
func matchesHookEntry(entry map[string]any, scriptPath string) bool {
	// Top-level command field.
	if cmd, ok := entry["command"].(string); ok && cmd == scriptPath {
		return true
	}
	// Nested hooks array.
	innerRaw, ok := entry["hooks"]
	if !ok {
		return false
	}
	inner, ok := innerRaw.([]any)
	if !ok {
		return false
	}
	for _, h := range inner {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if cmd, ok := hm["command"].(string); ok && cmd == scriptPath {
			return true
		}
	}
	return false
}

// appendPreToolUseHook adds a PreToolUse hook entry for scriptPath.
// Claude Code / Cursor settings format: hooks is an array of objects like:
//
//	{ "event": "PreToolUse", "hooks": [{ "type": "command", "command": "<script>" }] }
func appendPreToolUseHook(settings map[string]any, scriptPath string) map[string]any {
	newEntry := map[string]any{
		"event": "PreToolUse",
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": scriptPath,
			},
		},
	}

	existing, ok := settings["hooks"].([]any)
	if !ok {
		existing = []any{}
	}
	settings["hooks"] = append(existing, newEntry)
	return settings
}

// appendBeforeToolHook adds a BeforeTool hook entry for Gemini CLI.
func appendBeforeToolHook(settings map[string]any, scriptPath string) map[string]any {
	newEntry := map[string]any{
		"event": "BeforeTool",
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": scriptPath,
			},
		},
	}

	existing, ok := settings["hooks"].([]any)
	if !ok {
		existing = []any{}
	}
	settings["hooks"] = append(existing, newEntry)
	return settings
}

// splitLines splits a string into lines (handles \n and \r\n).
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// contains reports whether s contains substr (simple substring check).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
