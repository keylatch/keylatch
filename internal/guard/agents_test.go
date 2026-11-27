package guard_test

import "github.com/keylatch/keylatch/internal/guard"

// Harness IDs the tests install into; guard itself names only Claude Code.
const (
	agentCursor      guard.Agent = "cursor"
	agentCodex       guard.Agent = "codex"
	agentCopilot     guard.Agent = "copilot-cli"
	agentGemini      guard.Agent = "gemini-cli"
	agentOpenCode    guard.Agent = "opencode"
	agentAntigravity guard.Agent = "antigravity"
)
