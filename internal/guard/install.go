package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/harness/installer"
	"github.com/keylatch/keylatch/internal/harness/merge"
)

// Agent identifies a supported agent integration by its harness ID.
type Agent string

// AgentClaudeCode is the harness whose settings the guard package merges
// itself; every other harness goes through internal/harness.
const AgentClaudeCode Agent = "claude-code"

// SupportedAgents lists every agent a guard can be installed for.
var SupportedAgents = func() []Agent {
	var out []Agent
	for _, d := range harness.Installable() {
		out = append(out, Agent(d.ID))
	}
	return out
}()

// AgentHookMechanism describes the hook each agent uses and where it lives.
var AgentHookMechanism = func() map[Agent]string {
	out := map[Agent]string{}
	for _, d := range harness.Installable() {
		out[Agent(d.ID)] = fmt.Sprintf("%s (%s)", strings.Join(d.Hook.Events, ", "), d.HookDisplay())
	}
	return out
}()

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
	// ProjectDir installs into the project's own files instead of the user's.
	// "." means the current directory.
	ProjectDir string
	// ConfigDirs are extra Claude Code configuration directories to install
	// into, besides ~/.claude and $CLAUDE_CONFIG_DIR. Claude Code only.
	ConfigDirs []string
	// Upgrade rewrites an installed guard entry in place (new binary path,
	// matcher, timeout).
	Upgrade bool
	// DryRun computes the change and writes nothing.
	DryRun bool
	// KeylatchPath is the binary the hook runs; the running executable when
	// empty.
	KeylatchPath string
}

// Install wires the guard for agent into its hook configuration and returns the
// hook file's path. It is idempotent.
func Install(agent Agent, opts InstallOpts) (settingsPath string, err error) {
	d, err := descriptor(agent)
	if err != nil {
		return "", err
	}
	res, err := InstallHarness(d, installer.Options{Parts: installer.Parts{Guard: true}}, opts)
	if err != nil {
		return "", err
	}
	if len(res.Changes) == 0 {
		return "", fmt.Errorf("install-guard: %s: nothing to install", agent)
	}
	return res.Changes[0].Path, nil
}

// IsInstalled returns true when the guard for agent is already wired into the
// agent's hook configuration.
func IsInstalled(agent Agent, opts InstallOpts) (bool, error) {
	d, err := descriptor(agent)
	if err != nil {
		return false, err
	}
	env, err := harnessEnv(opts)
	if err != nil {
		return false, err
	}
	st := installer.Inspect(d, env)
	return st.Hook.Present, st.Hook.Err
}

func descriptor(agent Agent) (harness.Descriptor, error) {
	d, ok := harness.Resolve(string(agent))
	if !ok || d.Support != harness.SupportGuard {
		return harness.Descriptor{}, fmt.Errorf("install-guard: unsupported agent %q (supported: %v)", agent, SupportedAgents)
	}
	return d, nil
}

func harnessEnv(opts InstallOpts) (harness.Env, error) {
	env, err := harness.SystemEnv()
	if err != nil {
		return env, fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	if opts.ProjectDir != "" {
		if env.Project, err = filepath.Abs(opts.ProjectDir); err != nil {
			return env, fmt.Errorf("install-guard: resolve the project directory: %w", err)
		}
	}
	return env, nil
}

func keylatchBinary(path string) (string, error) {
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("install-guard: cannot locate the keylatch binary: %w", err)
		}
		path = exe
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot resolve the keylatch binary path: %w", err)
	}
	return abs, nil
}

// InstallHarness installs the parts of o.Parts for d: the hook, the MCP server
// and the rules block. The hook file of Claude Code is merged by this package
// (see InstallClaudeCode); everything else by internal/harness. The caller sets
// o.Parts; opts supplies the scope and the binary.
func InstallHarness(d harness.Descriptor, o installer.Options, opts InstallOpts) (installer.Result, error) {
	var err error
	if o.Env.Home == "" {
		if o.Env, err = harnessEnv(opts); err != nil {
			return installer.Result{}, err
		}
	}
	bin, err := keylatchBinary(opts.KeylatchPath)
	if err != nil {
		return installer.Result{}, err
	}
	o.Command, o.Binary = installer.GuardCommand(d, bin), bin
	if o.Server.Command == "" {
		o.Server.Command = bin
	}
	o.Upgrade, o.DryRun = opts.Upgrade, opts.DryRun
	res, err := installer.Install(d, o)
	if err == nil && !opts.DryRun && opts.ProjectDir == "" && o.Parts.Resolve().Guard {
		removeLegacyScripts(d)
		removeUnusedScript(opts)
	}
	if err != nil || d.ID != string(AgentClaudeCode) || !o.Parts.Resolve().Guard {
		return res, err
	}
	co := opts
	co.KeylatchPath = bin
	changes, err := InstallClaudeCode(co)
	var hook []installer.Change
	for _, c := range changes {
		hook = append(hook, installer.Change{Change: merge.Change{Path: c.Path, Changed: c.Changed, Diff: c.Diff, Backup: c.Backup}, Roles: []string{installer.RoleHook}})
	}
	res.Changes = append(hook, res.Changes...)
	return res, err
}

// UninstallHarness removes what InstallHarness wrote for d.
func UninstallHarness(d harness.Descriptor, o installer.Options, opts InstallOpts) (installer.Result, error) {
	var err error
	if o.Env.Home == "" {
		if o.Env, err = harnessEnv(opts); err != nil {
			return installer.Result{}, err
		}
	}
	o.DryRun = opts.DryRun
	res, err := installer.Uninstall(d, o)
	if err != nil || d.ID != string(AgentClaudeCode) || !o.Parts.Resolve().Guard {
		return res, err
	}
	var path string
	var removed bool
	if opts.DryRun {
		st := installer.Inspect(d, o.Env)
		path, removed = st.Hook.Path, st.Hook.Present
	} else if path, removed, err = uninstallClaudeCode(opts); err != nil {
		return res, err
	}
	res.Changes = append([]installer.Change{{Change: merge.Change{Path: path, Changed: removed}, Roles: []string{installer.RoleHook}}}, res.Changes...)
	removeUnusedScript(opts)
	return res, nil
}

// Uninstall removes the guard hook for agent. A guard that is not installed is
// not an error. It returns the hook file it edited and whether anything was
// removed.
func Uninstall(agent Agent, opts InstallOpts) (settingsPath string, removed bool, err error) {
	d, err := descriptor(agent)
	if err != nil {
		return "", false, err
	}
	res, err := UninstallHarness(d, installer.Options{Parts: installer.Parts{Guard: true}}, opts)
	if err != nil {
		return "", false, err
	}
	for _, c := range res.Changes {
		settingsPath = c.Path
		removed = removed || c.Changed
	}
	return settingsPath, removed, nil
}

// legacyScriptNames are the names earlier releases gave the per-agent scripts
// when they differ from the harness ID.
var legacyScriptNames = map[string]string{"gemini-cli": "gemini", "copilot-cli": "copilot"}

// removeLegacyScripts deletes the per-agent guard script earlier releases wrote
// for d, now that a hook runs the Go guard instead.
func removeLegacyScripts(d harness.Descriptor) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	name := d.ID
	if legacy, ok := legacyScriptNames[d.ID]; ok {
		name = legacy
	}
	for _, dir := range []string{"hooks", "guards"} {
		_ = os.Remove(filepath.Join(home, ".keylatch", dir, name+"-guard.sh"))
	}
}

// removeUnusedScript deletes the guard script earlier releases wrote, unless a
// harness's hook file still runs it.
func removeUnusedScript(opts InstallOpts) {
	home, err := os.UserHomeDir()
	if err != nil || opts.ProjectDir != "" {
		return
	}
	env := harness.Env{Home: home}
	for _, d := range harness.Installable() {
		if layout := d.Layout(env); layout.Hook != "" {
			if data, err := os.ReadFile(layout.Hook); err != nil && !os.IsNotExist(err) || strings.Contains(string(data), sharedGuardScript) {
				return
			}
		}
	}
	_ = os.Remove(filepath.Join(home, ".keylatch", "hooks", sharedGuardScript))
}

// --- Claude Code settings helpers ---

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
	data, err := encodeSettings(settings)
	if err != nil {
		return err
	}

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

// quoteArg wraps s in double quotes for a POSIX shell, escaping the characters
// that stay special inside them.
func quoteArg(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(s) + `"`
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

// legacyGuardRe matches the per-agent scripts older versions installed under
// ~/.keylatch/hooks or ~/.keylatch/guards.
var legacyGuardRe = regexp.MustCompile(`\.keylatch[/\\](hooks|guards)[/\\][a-z-]+-guard\.sh`)

const sharedGuardScript = "block-keylatch-exfiltration.sh"

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
