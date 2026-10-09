package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Agent identifies a supported agent integration.
type Agent string

const (
	AgentClaudeCode  Agent = "claude-code"
	AgentCursor      Agent = "cursor"
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
	AgentWindsurf,
	AgentCodex,
	AgentCopilot,
	AgentGemini,
	AgentOpenCode,
	AgentAntigravity,
}

// AgentHookMechanism describes the hook mechanism used by each agent.
var AgentHookMechanism = map[Agent]string{
	AgentClaudeCode:  "PreToolUse (~/.claude/settings.json)",
	AgentCursor:      "beforeShellExecution + beforeReadFile (~/.cursor/hooks.json)",
	AgentWindsurf:    "pre_run_command + pre_read_code (~/.codeium/windsurf/hooks.json)",
	AgentCodex:       "PreToolUse (~/.codex/hooks.json)",
	AgentCopilot:     "PreToolUse (~/.copilot/hooks/keylatch-guard.json)",
	AgentGemini:      "BeforeTool (~/.gemini/settings.json)",
	AgentOpenCode:    "tool.execute.before (TypeScript plugin)",
	AgentAntigravity: "PreToolUse (~/.gemini/config/hooks.json)",
}

// ProtectedPaths are the home-relative credential locations the guard script
// denies for direct agent reads. They are parsed from the script so the script
// holds the only list.
func ProtectedPaths() []string {
	m := protectedPathsRe.FindSubmatch(GuardScript)
	if m == nil {
		return nil
	}
	return strings.Fields(string(m[1]))
}

var protectedPathsRe = regexp.MustCompile(`(?m)^PROTECTED_PATHS="([^"]*)"`)

// CursorIgnorePatterns are the .cursorignore entries that keep agent file
// access away from the protected credential locations and .env files.
func CursorIgnorePatterns() []string {
	return append(ProtectedPaths(), ".env", ".env.*")
}

// InstallOpts controls where the hook is installed.
type InstallOpts struct {
	// ProjectDir installs into <ProjectDir>/.claude/settings.json instead of global.
	// When empty the global ~/.claude/settings.json is used. Claude Code only.
	ProjectDir string
}

// InstallResult carries the result of an Install call.
type InstallResult struct {
	// SettingsPath is the path to the settings file that was modified.
	SettingsPath string
	// Message is a human-readable summary of what was done.
	Message string
}

// Install writes the guard script for agent to disk and wires it into the agent's
// hook configuration. It is idempotent: if the hook is already present the function
// leaves the configuration unchanged. It returns the path of the configuration file.
func Install(agent Agent, opts InstallOpts) (settingsPath string, err error) {
	switch agent {
	case AgentClaudeCode:
		return installClaudeCode(opts)
	case AgentOpenCode:
		return installOpenCode(opts)
	case AgentCursor, AgentWindsurf, AgentCodex, AgentCopilot, AgentGemini, AgentAntigravity:
		return installHarness(agent)
	default:
		return "", fmt.Errorf("install-guard: unsupported agent %q (supported: %v)", agent, SupportedAgents)
	}
}

// IsInstalled returns true when the guard for agent is already wired into the
// agent's hook configuration.
func IsInstalled(agent Agent, opts InstallOpts) (bool, error) {
	switch agent {
	case AgentClaudeCode:
		settingsPath, err := resolveSettingsPath(opts)
		if err != nil {
			return false, err
		}
		scriptPath, err := guardScriptPath(agent, opts)
		if err != nil {
			return false, err
		}
		return configReferences(settingsPath, scriptPath)

	case AgentOpenCode:
		home, err := os.UserHomeDir()
		if err != nil {
			return false, fmt.Errorf("install-guard: cannot determine home directory: %w", err)
		}
		_, err = os.Stat(filepath.Join(home, ".config", "opencode", "plugins", "keylatch-guard"))
		return err == nil, nil

	case AgentCursor, AgentWindsurf, AgentCodex, AgentCopilot, AgentGemini, AgentAntigravity:
		home, err := os.UserHomeDir()
		if err != nil {
			return false, fmt.Errorf("install-guard: cannot determine home directory: %w", err)
		}
		scriptPath, err := guardScriptPath(agent, InstallOpts{})
		if err != nil {
			return false, err
		}
		return configReferences(harnessConfigPath(agent, home), hookCommand(agent, scriptPath))

	default:
		return false, fmt.Errorf("install-guard: unsupported agent %q (supported: %v)", agent, SupportedAgents)
	}
}

// configReferences reports whether the JSON file at path references command.
// A missing file means not installed.
func configReferences(path, command string) (bool, error) {
	settings, err := loadSettings(path)
	if err != nil {
		return false, err
	}
	return hookAlreadyInstalled(settings, command), nil
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

	// Repair the legacy array-format "hooks" field first (written by older
	// keylatch versions; silently ignored by current Claude Code), so an
	// already-present-but-broken hook gets fixed instead of skipped.
	settings, migrated := migrateLegacyHooks(settings)

	// Check for idempotency before mutating further.
	if hookAlreadyInstalled(settings, scriptPath) {
		if migrated {
			if err := saveSettings(settingsPath, settings); err != nil {
				return "", err
			}
		}
		return settingsPath, nil
	}

	// Append the PreToolUse hook.
	settings = appendClaudeCodePreToolUseHook(settings, scriptPath)

	// Persist the modified settings.
	if err := saveSettings(settingsPath, settings); err != nil {
		return "", err
	}

	return settingsPath, nil
}

// installHarness wires the shared guard script into a harness that reads a
// JSON hooks file. Each harness gets its own entry shape and `--harness` flag.
func installHarness(agent Agent) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	scriptPath, err := writeGuardScript(agent, InstallOpts{})
	if err != nil {
		return "", err
	}
	path := harnessConfigPath(agent, home)
	command := hookCommand(agent, scriptPath)

	settings, err := loadSettings(path)
	if err != nil {
		return "", err
	}
	migrated := false
	if agent == AgentCodex || agent == AgentGemini {
		settings, migrated = migrateLegacyHooks(settings)
	}
	settings, changed, err := addHarnessHook(agent, settings, command)
	if err != nil {
		return "", fmt.Errorf("install-guard: %s: %w", path, err)
	}
	if changed || migrated {
		if err := saveSettings(path, settings); err != nil {
			return "", err
		}
	}
	return path, nil
}

func harnessConfigPath(agent Agent, home string) string {
	switch agent {
	case AgentCursor:
		return filepath.Join(home, ".cursor", "hooks.json")
	case AgentWindsurf:
		return filepath.Join(home, ".codeium", "windsurf", "hooks.json")
	case AgentCodex:
		return filepath.Join(home, ".codex", "hooks.json")
	case AgentCopilot:
		base := os.Getenv("COPILOT_HOME")
		if base == "" {
			base = filepath.Join(home, ".copilot")
		}
		return filepath.Join(base, "hooks", "keylatch-guard.json")
	case AgentAntigravity:
		return filepath.Join(home, ".gemini", "config", "hooks.json")
	default:
		settingsPath := filepath.Join(home, ".gemini", "settings.json")
		if _, err := os.Stat(settingsPath); os.IsNotExist(err) {
			alt := filepath.Join(home, ".config", "gemini", "settings.json")
			if _, err := os.Stat(alt); err == nil {
				return alt
			}
		}
		return settingsPath
	}
}

// hookCommand is the command line a harness runs for the guard. Claude Code
// is the script's default harness and takes the bare path.
func hookCommand(agent Agent, scriptPath string) string {
	if agent == AgentClaudeCode {
		return scriptPath
	}
	return scriptPath + " --harness " + string(agent)
}

// addHarnessHook registers the guard in the harness's own hooks schema and
// reports whether the settings changed. Re-running it is a no-op.
func addHarnessHook(agent Agent, settings map[string]any, command string) (map[string]any, bool, error) {
	cmdEntry := map[string]any{"type": "command", "command": command}
	switch agent {
	case AgentCodex:
		cmdEntry["timeout"] = 30
		return addHookEntry(settings, "PreToolUse", command, map[string]any{"matcher": "Bash", "hooks": []any{cmdEntry}})
	case AgentGemini:
		cmdEntry["name"] = "keylatch-guard"
		cmdEntry["timeout"] = 10000
		return addHookEntry(settings, "BeforeTool", command, map[string]any{"matcher": "run_shell_command|read_file|read_many_files", "hooks": []any{cmdEntry}})
	case AgentCursor:
		if _, ok := settings["version"]; !ok {
			settings["version"] = 1
		}
		return addHookEntries(settings, command, []string{"beforeShellExecution", "beforeReadFile"}, func() map[string]any {
			return map[string]any{"command": command, "timeout": 10, "failClosed": true}
		})
	case AgentWindsurf:
		return addHookEntries(settings, command, []string{"pre_run_command", "pre_read_code"}, func() map[string]any {
			return map[string]any{"command": command, "show_output": false}
		})
	case AgentCopilot:
		if _, ok := settings["version"]; !ok {
			settings["version"] = 1
		}
		return addHookEntry(settings, "PreToolUse", command, map[string]any{"type": "command", "bash": command, "timeoutSec": 10})
	case AgentAntigravity:
		before, _ := json.Marshal(settings["keylatch-guard"])
		cmdEntry["timeout"] = 10
		settings["keylatch-guard"] = map[string]any{
			"enabled": true,
			"PreToolUse": []any{
				map[string]any{"matcher": "run_command|view_file", "hooks": []any{cmdEntry}},
			},
		}
		after, _ := json.Marshal(settings["keylatch-guard"])
		return settings, string(before) != string(after), nil
	default:
		return nil, false, fmt.Errorf("no hook schema for agent %q", agent)
	}
}

// addHookEntries registers one entry under each event.
func addHookEntries(settings map[string]any, command string, events []string, entry func() map[string]any) (map[string]any, bool, error) {
	changed := false
	for _, event := range events {
		var added bool
		var err error
		settings, added, err = addHookEntry(settings, event, command, entry())
		if err != nil {
			return nil, false, err
		}
		changed = changed || added
	}
	return settings, changed, nil
}

// addHookEntry appends entry under hooks.<event> unless command is already
// registered there, refusing to overwrite a "hooks" value that is not an object.
func addHookEntry(settings map[string]any, event, command string, entry map[string]any) (map[string]any, bool, error) {
	hooksObj := map[string]any{}
	if existing, present := settings["hooks"]; present {
		obj, ok := existing.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("existing \"hooks\" value is not an object")
		}
		hooksObj = obj
	}
	arr, _ := hooksObj[event].([]any)
	if containsString(arr, command) {
		return settings, false, nil
	}
	hooksObj[event] = append(arr, entry)
	settings["hooks"] = hooksObj
	return settings, true, nil
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
	if agent == AgentOpenCode {
		return "keylatch-guard.ts"
	}
	return "block-keylatch-exfiltration.sh"
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
	if agent == AgentOpenCode {
		return OpenCodeScript, nil
	}
	return GuardScript, nil
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
	data, err := json.MarshalIndent(settings, "", " ")
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

// hookAlreadyInstalled returns true when command appears anywhere in settings
// as a string value, whatever schema the harness uses.
func hookAlreadyInstalled(settings map[string]any, command string) bool {
	return containsString(settings, command)
}

func containsString(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []any:
		for _, e := range t {
			if containsString(e, want) {
				return true
			}
		}
	case map[string]any:
		for _, e := range t {
			if containsString(e, want) {
				return true
			}
		}
	}
	return false
}

// migrateLegacyHooks converts a legacy array-format "hooks" field
// (written by older keylatch versions; silently ignored by current Claude
// Code) into the object format keyed by each entry's "event" field. Returns
// the settings and whether a migration took place. Settings without a legacy
// array are returned unchanged.
func migrateLegacyHooks(settings map[string]any) (map[string]any, bool) {
	legacy, isArr := settings["hooks"].([]any)
	if !isArr {
		return settings, false
	}
	hooksObj := map[string]any{}
	var leftovers []any
	for _, raw := range legacy {
		entry, isMap := raw.(map[string]any)
		if !isMap {
			leftovers = append(leftovers, raw)
			continue
		}
		event, _ := entry["event"].(string)
		if event == "" {
			leftovers = append(leftovers, raw)
			continue
		}
		migrated := map[string]any{}
		for k, v := range entry {
			if k != "event" {
				migrated[k] = v
			}
		}
		arr, _ := hooksObj[event].([]any)
		hooksObj[event] = append(arr, migrated)
	}
	if len(leftovers) > 0 {
		// Entries with no "event" field have no slot in the object format.
		// Park them under a backup key instead of silently dropping them.
		settings["hooksLegacy"] = leftovers
	}
	settings["hooks"] = hooksObj
	return settings, true
}

// appendClaudeCodePreToolUseHook adds a PreToolUse hook entry for scriptPath
// using the Claude Code settings schema, where "hooks" is an object mapping
// event names to matcher groups:
//
//	"hooks": { "PreToolUse": [{ "hooks": [{ "type": "command", "command": "<script>" }] }] }
func appendClaudeCodePreToolUseHook(settings map[string]any, scriptPath string) map[string]any {
	hooksObj, ok := settings["hooks"].(map[string]any)
	if !ok {
		hooksObj = map[string]any{}
	}

	arr, _ := hooksObj["PreToolUse"].([]any)
	hooksObj["PreToolUse"] = append(arr, map[string]any{
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": scriptPath,
			},
		},
	})
	settings["hooks"] = hooksObj
	return settings
}
