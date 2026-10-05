package llmcontext

// Signal represents a single LLM session detection signal.
type Signal struct {
	EnvKey    string
	MatchRule string // "non-empty" | "llm-session" | "equals:<value>"
	Label     string // returned by Reasons()
}

// Signals is the canonical ordered list of all detection signals.
// IsLLMSession and Reasons both derive from this slice.
//
// These variables are set by the harnesses in the processes they spawn, so
// they are a convenience label only: the classified process can unset or set
// any of them. They must never be the only thing standing between an agent
// and a privileged operation.
var Signals = []Signal{
	// Claude Code: CLAUDECODE=1 is documented; CLAUDE_CODE_ENTRYPOINT is set
	// in practice (cli, sdk-ts, ...) but undocumented.
	{EnvKey: "CLAUDECODE", MatchRule: "non-empty", Label: "CLAUDECODE"},
	{EnvKey: "CLAUDE_CODE_ENTRYPOINT", MatchRule: "non-empty", Label: "CLAUDE_CODE_ENTRYPOINT"},
	// Codex CLI sets CODEX_SANDBOX only under the macOS seatbelt sandbox and
	// CODEX_SANDBOX_NETWORK_DISABLED only when network access is off.
	{EnvKey: "CODEX_SANDBOX", MatchRule: "non-empty", Label: "CODEX_SANDBOX"},
	{EnvKey: "CODEX_SANDBOX_NETWORK_DISABLED", MatchRule: "non-empty", Label: "CODEX_SANDBOX_NETWORK_DISABLED"},
	// CURSOR_AGENT is set in the agent terminal. CURSOR_TRACE_ID is not
	// publicly documented and may also be present in human Cursor terminals;
	// over-detection only restricts, so it is kept.
	{EnvKey: "CURSOR_AGENT", MatchRule: "non-empty", Label: "CURSOR_AGENT"},
	{EnvKey: "CURSOR_TRACE_ID", MatchRule: "non-empty", Label: "CURSOR_TRACE_ID"},
	{EnvKey: "GEMINI_CLI", MatchRule: "non-empty", Label: "GEMINI_CLI"},
	{EnvKey: "OPENCODE", MatchRule: "non-empty", Label: "OPENCODE"},
	{EnvKey: "CREDENTIALS_LLM_SESSION", MatchRule: "llm-session", Label: "CREDENTIALS_LLM_SESSION"},
	// Legacy names kept for users who export them manually; no harness sets them.
	{EnvKey: "CLAUDE_CODE", MatchRule: "non-empty", Label: "CLAUDE_CODE"},
	{EnvKey: "CODEX_ENV", MatchRule: "non-empty", Label: "CODEX_ENV"},
	{EnvKey: "CURSOR_SESSION", MatchRule: "non-empty", Label: "CURSOR_SESSION"},
	{EnvKey: "AIDER_SESSION", MatchRule: "non-empty", Label: "AIDER_SESSION"},
	{EnvKey: "GEMINI_SESSION", MatchRule: "non-empty", Label: "GEMINI_SESSION"},
	{EnvKey: "OPENCODE_SESSION", MatchRule: "non-empty", Label: "OPENCODE_SESSION"},
}
