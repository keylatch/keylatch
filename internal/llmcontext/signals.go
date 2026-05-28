package llmcontext

// Signal represents a single LLM session detection signal.
type Signal struct {
	EnvKey    string
	MatchRule string // "non-empty" | "llm-session" | "equals:<value>"
	Label     string // returned by Reasons()
}

// Signals is the canonical ordered list of all detection signals.
// IsLLMSession and Reasons both derive from this slice.
// S0-2: original three signals (Claude Code, Codex, generic session flag).
// S3-6: additional agent signals (Cursor, Aider, Gemini CLI, OpenCode).
var Signals = []Signal{
	{EnvKey: "CLAUDE_CODE", MatchRule: "non-empty", Label: "CLAUDE_CODE"},
	{EnvKey: "CODEX_ENV", MatchRule: "non-empty", Label: "CODEX_ENV"},
	{EnvKey: "CREDENTIALS_LLM_SESSION", MatchRule: "llm-session", Label: "CREDENTIALS_LLM_SESSION"},
	{EnvKey: "CURSOR_SESSION", MatchRule: "non-empty", Label: "CURSOR_SESSION"},
	{EnvKey: "AIDER_SESSION", MatchRule: "non-empty", Label: "AIDER_SESSION"},
	{EnvKey: "GEMINI_SESSION", MatchRule: "non-empty", Label: "GEMINI_SESSION"},
	{EnvKey: "OPENCODE_SESSION", MatchRule: "non-empty", Label: "OPENCODE_SESSION"},
}
