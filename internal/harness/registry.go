// Package harness describes the agent harnesses Keylatch recognizes: the
// environment variables each one sets in the processes it spawns and the
// executable names it runs under. It is the only list of harness signals in
// the code base; detection, actor inference and the env documentation derive
// from it. It imports only the standard library.
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

// Descriptor describes one harness. HookFormat and MCPFormat stay empty until
// the per-harness installers record the formats they write.
type Descriptor struct {
	ID          string
	Name        string
	Env         []EnvSignal
	LegacyEnv   []EnvSignal
	Executables []string
	HookFormat  string
	MCPFormat   string
}

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
	},
	{
		ID:          "gemini-cli",
		Name:        "Gemini CLI",
		Env:         []EnvSignal{{Name: "GEMINI_CLI", Match: NonEmpty, Note: `set to "1" by Gemini CLI in shell commands`}},
		LegacyEnv:   []EnvSignal{{Name: "GEMINI_SESSION", Match: NonEmpty, Note: "legacy manual label"}},
		Executables: []string{"gemini"},
	},
	{
		ID:          "opencode",
		Name:        "OpenCode",
		Env:         []EnvSignal{{Name: "OPENCODE", Match: NonEmpty, Note: `set to "1" by OpenCode`}},
		LegacyEnv:   []EnvSignal{{Name: "OPENCODE_SESSION", Match: NonEmpty, Note: "legacy manual label"}},
		Executables: []string{"opencode"},
	},
	{
		ID:          "aider",
		Name:        "Aider",
		LegacyEnv:   []EnvSignal{{Name: "AIDER_SESSION", Match: NonEmpty, Note: "manual label; Aider sets nothing"}},
		Executables: []string{"aider"},
	},
	{
		ID:          "copilot-cli",
		Name:        "GitHub Copilot CLI",
		Executables: []string{"copilot"},
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
