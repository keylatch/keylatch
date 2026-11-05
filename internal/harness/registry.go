// Package harness describes the agent harnesses Keylatch recognizes and
// supports: the environment variables each one sets in the processes it
// spawns, the executable names it runs under, and where its configuration
// lives (hook file, MCP file, rules file) and in what format. It is the only
// list of harness signals and harness configuration paths in the code base;
// detection, actor inference, the installers, doctor and the documentation
// derive from it.
package harness

import "strings"

// Match decides whether an environment value counts as a signal.
type Match int

const (
	// NonEmpty fires on any non-empty value.
	NonEmpty Match = iota
	// NotZero fires on any non-empty value except "0".
	NotZero
)

// Fires reports whether value satisfies m.
func (m Match) Fires(value string) bool {
	switch m {
	case NonEmpty:
		return value != ""
	case NotZero:
		return value != "" && value != "0"
	default:
		return false
	}
}

// EnvSignal is one environment variable that marks an agent session.
type EnvSignal struct {
	Name  string
	Match Match
	Note  string
}

// Support is how far Keylatch goes for a harness.
type Support string

const (
	// SupportGuard: detection, a pre-tool hook that runs the Keylatch guard, an
	// MCP registration and a rules snippet.
	SupportGuard Support = "guard"
	// SupportDetect: the harness is recognized and its MCP client can use
	// Keylatch, but it has no hook mechanism to install.
	SupportDetect Support = "detect"
	// SupportLaunchOnly: Keylatch starts the harness through `keylatch launch`
	// and edits none of its files.
	SupportLaunchOnly Support = "launch-only"
)

// File formats the installers read and write.
const (
	FormatJSON      = "json-object"
	FormatTOML      = "toml"
	FormatPluginDir = "plugin-dir"
)

// Dir says where a harness keeps its user-level configuration.
type Dir struct {
	// Env, when set in the environment, names the directory itself
	// (CLAUDE_CONFIG_DIR, CODEX_HOME, COPILOT_HOME).
	Env string
	// EnvHome, when set in the environment, replaces the home directory the
	// Rel path hangs from (GEMINI_CLI_HOME).
	EnvHome string
	// Rel is the path under the home directory.
	Rel []string
	// XDG places the directory under $XDG_CONFIG_HOME, or ~/.config when that
	// is unset, instead of under Rel.
	XDG []string
}

// HookSpec describes the harness's pre-tool hook file.
type HookSpec struct {
	// File is the hook file, relative to the configuration directory.
	File string
	// ProjectFile is the project-level equivalent, relative to the project
	// root; empty when the harness has none.
	ProjectFile string
	// Format is FormatJSON, FormatTOML or FormatPluginDir.
	Format string
	// Events are the hook event names the installer registers under.
	Events []string
}

// MCPSpec describes where the harness lists MCP servers.
type MCPSpec struct {
	// File is relative to the configuration directory.
	File string
	// HomeFile, when set, is where File lives when the configuration directory
	// was not overridden, relative to the home directory (Claude Code keeps
	// ~/.claude.json beside ~/.claude, not inside it).
	HomeFile string
	// Format is FormatJSON or FormatTOML.
	Format string
	// Key is the object (or TOML table) that holds the servers.
	Key string
}

// RulesSpec describes the file whose instructions the agent reads.
type RulesSpec struct {
	// File is relative to the configuration directory; empty when the harness
	// has no user-level rules file.
	File string
	// ProjectFile is relative to the project root.
	ProjectFile string
}

// Descriptor describes one harness.
type Descriptor struct {
	ID          string
	Name        string
	Env         []EnvSignal
	LegacyEnv   []EnvSignal
	Executables []string

	Support Support
	Config  Dir
	Hook    *HookSpec
	MCP     *MCPSpec
	Rules   *RulesSpec
	// Adapter names the payload and deny contract `keylatch guard hook
	// --harness` uses for this harness.
	Adapter string
	// Detect, when set, is a path under the configuration directory that
	// exists only where the harness is installed; it is for a directory several
	// tools share (Antigravity and Gemini CLI both use ~/.gemini).
	Detect string
	// Protected lists further files and directories (a trailing slash marks a
	// directory), as slash-separated path suffixes, whose edit could switch the
	// guard off or run code in the harness.
	Protected []string
	// Verified says what the formats were last checked against. The drift job
	// re-checks them nightly against the published releases; empty means the
	// formats come from no source yet.
	Verified string
}

// DocsVerified marks formats taken from the vendors' published documentation.
// No harness release has been run against them in this repository; the drift
// workflow does that.
const DocsVerified = "vendor docs, 2026-10-09"

var descriptors = []Descriptor{
	{
		ID:   "claude-code",
		Name: "Claude Code",
		Env: []EnvSignal{
			{Name: "CLAUDECODE", Match: NonEmpty, Note: `set to "1" by Claude Code in the shells it spawns`},
			{Name: "CLAUDE_CODE_ENTRYPOINT", Match: NonEmpty, Note: "set by Claude Code (cli, sdk-ts, ...)"},
		},
		LegacyEnv:   []EnvSignal{{Name: "CLAUDE_CODE", Match: NonEmpty, Note: "legacy manual label"}},
		Executables: []string{"claude"},
		Support:     SupportGuard,
		Config:      Dir{Env: "CLAUDE_CONFIG_DIR", Rel: []string{".claude"}},
		Hook:        &HookSpec{File: "settings.json", ProjectFile: ".claude/settings.json", Format: FormatJSON, Events: []string{"PreToolUse"}},
		MCP:         &MCPSpec{File: ".claude.json", HomeFile: ".claude.json", Format: FormatJSON, Key: "mcpServers"},
		Rules:       &RulesSpec{File: "CLAUDE.md", ProjectFile: "CLAUDE.md"},
		Adapter:     "claude-code",
		Protected:   []string{".claude/settings.local.json", ".claude/hooks/", "managed-settings.json"},
		Verified:    DocsVerified,
	},
	{
		ID:   "codex",
		Name: "Codex CLI",
		Env: []EnvSignal{
			{Name: "CODEX_SANDBOX", Match: NonEmpty, Note: "set by Codex CLI under its macOS sandbox"},
			{Name: "CODEX_SANDBOX_NETWORK_DISABLED", Match: NonEmpty, Note: "set by Codex CLI when network access is off"},
		},
		LegacyEnv:   []EnvSignal{{Name: "CODEX_ENV", Match: NonEmpty, Note: "legacy manual label"}},
		Executables: []string{"codex"},
		Support:     SupportGuard,
		Config:      Dir{Env: "CODEX_HOME", Rel: []string{".codex"}},
		Hook:        &HookSpec{File: "hooks.json", Format: FormatJSON, Events: []string{"PreToolUse"}},
		MCP:         &MCPSpec{File: "config.toml", Format: FormatTOML, Key: "mcp_servers"},
		Rules:       &RulesSpec{File: "AGENTS.md", ProjectFile: "AGENTS.md"},
		Adapter:     "codex",
		Verified:    DocsVerified,
	},
	{
		ID:   "cursor",
		Name: "Cursor",
		Env: []EnvSignal{
			{Name: "CURSOR_AGENT", Match: NonEmpty, Note: `set to "1" in the Cursor agent terminal`},
			// Also present in some human Cursor terminals; over-detection only restricts.
			{Name: "CURSOR_TRACE_ID", Match: NonEmpty, Note: "set by Cursor"},
		},
		LegacyEnv:   []EnvSignal{{Name: "CURSOR_SESSION", Match: NonEmpty, Note: "legacy manual label"}},
		Executables: []string{"cursor-agent"},
		Support:     SupportGuard,
		Config:      Dir{Rel: []string{".cursor"}},
		Hook:        &HookSpec{File: "hooks.json", ProjectFile: ".cursor/hooks.json", Format: FormatJSON, Events: []string{"beforeShellExecution", "beforeReadFile", "beforeMCPExecution"}},
		MCP:         &MCPSpec{File: "mcp.json", Format: FormatJSON, Key: "mcpServers"},
		Rules:       &RulesSpec{ProjectFile: ".cursor/rules/keylatch.mdc"},
		Adapter:     "cursor",
		Verified:    DocsVerified,
	},
	{
		ID:          "gemini-cli",
		Name:        "Gemini CLI",
		Env:         []EnvSignal{{Name: "GEMINI_CLI", Match: NonEmpty, Note: `set to "1" by Gemini CLI in shell commands`}},
		LegacyEnv:   []EnvSignal{{Name: "GEMINI_SESSION", Match: NonEmpty, Note: "legacy manual label"}},
		Executables: []string{"gemini"},
		Support:     SupportGuard,
		Config:      Dir{EnvHome: "GEMINI_CLI_HOME", Rel: []string{".gemini"}},
		Hook:        &HookSpec{File: "settings.json", ProjectFile: ".gemini/settings.json", Format: FormatJSON, Events: []string{"BeforeTool"}},
		MCP:         &MCPSpec{File: "settings.json", Format: FormatJSON, Key: "mcpServers"},
		Rules:       &RulesSpec{File: "GEMINI.md", ProjectFile: "GEMINI.md"},
		Adapter:     "gemini-cli",
		Verified:    DocsVerified,
	},
	{
		ID:          "opencode",
		Name:        "OpenCode",
		Env:         []EnvSignal{{Name: "OPENCODE", Match: NonEmpty, Note: `set to "1" by OpenCode`}},
		LegacyEnv:   []EnvSignal{{Name: "OPENCODE_SESSION", Match: NonEmpty, Note: "legacy manual label"}},
		Executables: []string{"opencode"},
		Support:     SupportGuard,
		Config:      Dir{XDG: []string{"opencode"}},
		Hook:        &HookSpec{File: "plugins/keylatch-guard.ts", ProjectFile: ".opencode/plugins/keylatch-guard.ts", Format: FormatPluginDir, Events: []string{"tool.execute.before"}},
		MCP:         &MCPSpec{File: "opencode.json", Format: FormatJSON, Key: "mcp"},
		Rules:       &RulesSpec{File: "AGENTS.md", ProjectFile: "AGENTS.md"},
		Adapter:     "opencode",
		Verified:    DocsVerified,
	},
	{
		ID:          "copilot-cli",
		Name:        "GitHub Copilot CLI",
		Executables: []string{"copilot"},
		Support:     SupportGuard,
		Config:      Dir{Env: "COPILOT_HOME", Rel: []string{".copilot"}},
		Hook:        &HookSpec{File: "hooks/keylatch-guard.json", ProjectFile: ".github/hooks/keylatch-guard.json", Format: FormatJSON, Events: []string{"preToolUse"}},
		MCP:         &MCPSpec{File: "mcp-config.json", Format: FormatJSON, Key: "mcpServers"},
		Rules:       &RulesSpec{File: "copilot-instructions.md", ProjectFile: ".github/copilot-instructions.md"},
		Adapter:     "copilot-cli",
		Verified:    DocsVerified,
	},
	{
		ID:      "antigravity",
		Name:    "Antigravity",
		Support: SupportGuard,
		Config:  Dir{Rel: []string{".gemini"}},
		Hook:    &HookSpec{File: "config/hooks.json", ProjectFile: ".agents/hooks.json", Format: FormatJSON, Events: []string{"PreToolUse"}},
		MCP:     &MCPSpec{File: "antigravity/mcp_config.json", Format: FormatJSON, Key: "mcpServers"},
		Rules:   &RulesSpec{File: "GEMINI.md", ProjectFile: ".agents/rules/keylatch.md"},
		Adapter: "antigravity",
		Detect:  "antigravity",
	},
	{
		ID:          "windsurf",
		Name:        "Windsurf",
		Executables: []string{"windsurf"},
		Support:     SupportGuard,
		Config:      Dir{Rel: []string{".codeium", "windsurf"}},
		Hook:        &HookSpec{File: "hooks.json", ProjectFile: ".windsurf/hooks.json", Format: FormatJSON, Events: []string{"pre_run_command", "pre_read_code", "pre_write_code", "pre_mcp_tool_use"}},
		MCP:         &MCPSpec{File: "mcp_config.json", Format: FormatJSON, Key: "mcpServers"},
		Rules:       &RulesSpec{File: "memories/global_rules.md", ProjectFile: ".windsurf/rules/keylatch.md"},
		Adapter:     "windsurf",
	},
	{
		ID:          "aider",
		Name:        "Aider",
		LegacyEnv:   []EnvSignal{{Name: "AIDER_SESSION", Match: NonEmpty, Note: "manual label; Aider sets nothing"}},
		Executables: []string{"aider"},
		Support:     SupportLaunchOnly,
	},
	{
		ID:          "goose",
		Name:        "Goose",
		Executables: []string{"goose"},
		Support:     SupportLaunchOnly,
	},
}

// Manual labels mark a shell as an agent session by hand.
const (
	ManualLabel       = "KEYLATCH_AGENT_SESSION"
	LegacyManualLabel = "CREDENTIALS_LLM_SESSION"
)

// ManualSignals are the manual labels as signals.
var ManualSignals = []EnvSignal{
	{Name: ManualLabel, Match: NotZero, Note: `set to "1" to mark a shell as an agent session`},
	{Name: LegacyManualLabel, Match: NotZero, Note: "legacy manual label"},
}

// aliases maps the names earlier releases and users spell to harness IDs.
var aliases = map[string]string{
	"claude": "claude-code", "claude_code": "claude-code", "claudecode": "claude-code",
	"gemini": "gemini-cli", "copilot": "copilot-cli", "agy": "antigravity",
}

// All returns every harness descriptor in detection order.
func All() []Descriptor {
	out := make([]Descriptor, len(descriptors))
	copy(out, descriptors)
	return out
}

// Lookup returns the descriptor with the given ID.
func Lookup(id string) (Descriptor, bool) {
	for _, d := range descriptors {
		if d.ID == id {
			return d, true
		}
	}
	return Descriptor{}, false
}

// Resolve finds a harness by ID or by one of the spellings users type
// ("gemini" for "gemini-cli").
func Resolve(name string) (Descriptor, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if id, ok := aliases[name]; ok {
		name = id
	}
	return Lookup(name)
}

// Installable returns the harnesses Keylatch can install a guard into.
func Installable() []Descriptor {
	var out []Descriptor
	for _, d := range descriptors {
		if d.Support == SupportGuard {
			out = append(out, d)
		}
	}
	return out
}

// ByExecutable returns the harness that runs under the executable name, which
// may carry a directory and, on Windows, a ".exe" suffix.
func ByExecutable(name string) (Descriptor, bool) {
	base := NormalizeExecutable(name)
	if base == "" {
		return Descriptor{}, false
	}
	for _, d := range descriptors {
		for _, exe := range d.Executables {
			if exe == base {
				return d, true
			}
		}
	}
	return Descriptor{}, false
}

// NormalizeExecutable reduces a path or process name to a lower-case base
// name without a ".exe" suffix.
func NormalizeExecutable(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.TrimSuffix(name, ".exe")
}

// Signals returns every environment signal: each harness's current names,
// then the legacy aliases, then the manual labels.
func Signals() []OwnedSignal {
	var out []OwnedSignal
	for _, d := range descriptors {
		for _, s := range d.Env {
			out = append(out, OwnedSignal{EnvSignal: s, Harness: d.ID})
		}
	}
	for _, d := range descriptors {
		for _, s := range d.LegacyEnv {
			out = append(out, OwnedSignal{EnvSignal: s, Harness: d.ID, Legacy: true})
		}
	}
	for _, s := range ManualSignals {
		out = append(out, OwnedSignal{EnvSignal: s, Legacy: s.Name != ManualLabel})
	}
	return out
}

// OwnedSignal is an EnvSignal with the harness that sets it ("" for a
// manual label).
type OwnedSignal struct {
	EnvSignal
	Harness string
	Legacy  bool
}
