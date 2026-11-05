package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
		return configReferences(settingsPath, hookCommand(agent, scriptPath))

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

	// Replace entries written by earlier versions (a bare script path, the old
	// per-agent scripts) with the current command.
	command := hookCommand(AgentClaudeCode, scriptPath)
	pruned := pruneStaleHooks(settings, command)

	if hookAlreadyInstalled(settings, command) {
		if migrated || pruned {
			if err := saveSettings(settingsPath, settings); err != nil {
				return "", err
			}
		}
		removeLegacyScripts(AgentClaudeCode, opts)
		return settingsPath, nil
	}

	settings = appendClaudeCodePreToolUseHook(settings, command)
	if err := saveSettings(settingsPath, settings); err != nil {
		return "", err
	}
	removeLegacyScripts(AgentClaudeCode, opts)
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
	pruned := pruneStaleHooks(settings, command)
	settings, changed, err := addHarnessHook(agent, settings, command)
	if err != nil {
		return "", fmt.Errorf("install-guard: %s: %w", path, err)
	}
	if changed || migrated || pruned {
		if err := saveSettings(path, settings); err != nil {
			return "", err
		}
	}
	if agent == AgentCursor {
		if err := removeLegacyCursorSettingsHook(home); err != nil {
			return "", err
		}
	}
	removeLegacyScripts(agent, InstallOpts{})
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
// is the script's default harness and takes no flag. The script path is always
// quoted so a home directory with a space survives the harness's shell. On
// Windows the harness hands the line to a shell that drops backslashes and
// cannot run a .sh file directly, so the script runs through bash with a
// forward-slash path.
func hookCommand(agent Agent, scriptPath string) string {
	command := quoteArg(scriptPath)
	if runtime.GOOS == "windows" {
		command = `bash ` + quoteArg(filepath.ToSlash(scriptPath))
	}
	if agent == AgentClaudeCode {
		return command
	}
	return command + " --harness " + string(agent)
}

// quoteArg wraps s in double quotes for a POSIX shell, escaping the characters
// that stay special inside them.
func quoteArg(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(s) + `"`
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
		settings, added, err := addHookEntry(settings, "BeforeTool", command, map[string]any{"matcher": geminiMatcher, "hooks": []any{cmdEntry}})
		if err != nil {
			return nil, false, err
		}
		return settings, setGroupMatcher(settings, "BeforeTool", command, geminiMatcher) || added, nil
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

// geminiMatcher selects the Gemini tools the guard sees: the shell and every
// tool that reads file content.
const geminiMatcher = "run_shell_command|read_file|read_many_files|glob|search_file_content|grep_search"

// setGroupMatcher points the matcher group that runs command at matcher, so an
// install over an older version picks up newly guarded tools.
func setGroupMatcher(settings map[string]any, event, command, matcher string) bool {
	hooksObj, _ := settings["hooks"].(map[string]any)
	groups, _ := hooksObj[event].([]any)
	changed := false
	for _, g := range groups {
		group, ok := g.(map[string]any)
		if !ok || !containsString(group, command) || group["matcher"] == matcher {
			continue
		}
		group["matcher"] = matcher
		changed = true
	}
	return changed
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

// appendClaudeCodePreToolUseHook adds a PreToolUse hook entry running command
// using the Claude Code settings schema, where "hooks" is an object mapping
// event names to matcher groups:
//
//	"hooks": { "PreToolUse": [{ "hooks": [{ "type": "command", "command": "<command>" }] }] }
func appendClaudeCodePreToolUseHook(settings map[string]any, command string) map[string]any {
	hooksObj, ok := settings["hooks"].(map[string]any)
	if !ok {
		hooksObj = map[string]any{}
	}

	arr, _ := hooksObj["PreToolUse"].([]any)
	hooksObj["PreToolUse"] = append(arr, map[string]any{
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": command,
			},
		},
	})
	settings["hooks"] = hooksObj
	return settings
}

// legacyGuardRe matches the per-agent scripts older versions installed under
// ~/.keylatch/hooks or ~/.keylatch/guards.
var legacyGuardRe = regexp.MustCompile(`\.keylatch[/\\](hooks|guards)[/\\][a-z-]+-guard\.sh`)

const sharedGuardScript = "block-keylatch-exfiltration.sh"

// pruneStaleHooks removes hook entries that run a guard script other than
// command: an earlier spelling of the current script path, or one of the old
// per-agent scripts. Containers the removal empties are removed with it. It
// reports whether anything changed.
func pruneStaleHooks(settings map[string]any, command string) bool {
	_, changed := pruneHooks(settings, func(cmd string) bool {
		return cmd != command && (strings.Contains(cmd, sharedGuardScript) || legacyGuardRe.MatchString(cmd))
	})
	return changed
}

func pruneHooks(v any, stale func(string) bool) (any, bool) {
	switch t := v.(type) {
	case []any:
		out := make([]any, 0, len(t))
		changed := false
		for _, e := range t {
			em, isMap := e.(map[string]any)
			if isMap && entryIsStale(em, stale) {
				changed = true
				continue
			}
			_, hadHooks := em["hooks"]
			ne, c := pruneHooks(e, stale)
			if c {
				changed = true
				nm, _ := ne.(map[string]any)
				if _, hasHooks := nm["hooks"]; isMap && hadHooks && !hasHooks {
					continue
				}
			}
			out = append(out, ne)
		}
		return out, changed
	case map[string]any:
		changed := false
		for k, e := range t {
			ne, c := pruneHooks(e, stale)
			if !c {
				continue
			}
			changed = true
			if isEmptyContainer(ne) {
				delete(t, k)
			} else {
				t[k] = ne
			}
		}
		return t, changed
	}
	return v, false
}

func entryIsStale(m map[string]any, stale func(string) bool) bool {
	for _, key := range []string{"command", "bash"} {
		if cmd, ok := m[key].(string); ok && stale(cmd) {
			return true
		}
	}
	return false
}

func isEmptyContainer(v any) bool {
	switch t := v.(type) {
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// removeLegacyScripts deletes the per-agent script older versions wrote for
// agent, next to the current one and in the older guards directory.
func removeLegacyScripts(agent Agent, opts InstallOpts) {
	name := string(agent) + "-guard.sh"
	var dirs []string
	if dir, err := guardScriptDir(agent, opts); err == nil {
		dirs = append(dirs, dir, filepath.Join(filepath.Dir(dir), "guards"))
	}
	for _, dir := range dirs {
		_ = os.Remove(filepath.Join(dir, name))
	}
}

// removeLegacyCursorSettingsHook drops the guard entry an older version put in
// ~/.cursor/settings.json, which Cursor does not read for hooks.
func removeLegacyCursorSettingsHook(home string) error {
	path := filepath.Join(home, ".cursor", "settings.json")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	settings, err := loadSettings(path)
	if err != nil {
		return err
	}
	if !pruneStaleHooks(settings, "") {
		return nil
	}
	return saveSettings(path, settings)
}
