// Package guard embeds the agent guard scripts shipped with keylatch.
// The embedded scripts are written to disk and wired into agent tool-call hooks
// by the `keylatch install-guard` command.
package guard

import _ "embed"

// ClaudeCodeScript is the pre-tool-use hook script that blocks credential
// exfiltration attempts originating from a Claude Code LLM session.
//
//go:embed scripts/block-keylatch-exfiltration.sh
var ClaudeCodeScript []byte

// CursorScript is the pre-tool-use hook script for Cursor.
//
//go:embed scripts/cursor-guard.sh
var CursorScript []byte

// AiderScript is the pre-tool-use hook script for Aider.
//
//go:embed scripts/aider-guard.sh
var AiderScript []byte

// WindsurfScript is the guard script for Windsurf (manual use only;
// Windsurf does not yet expose a hook API).
//
//go:embed scripts/windsurf-guard.sh
var WindsurfScript []byte

// CodexScript is the PreToolUse hook script for Codex CLI.
//
//go:embed scripts/codex-guard.sh
var CodexScript []byte

// CopilotScript is the guard script for GitHub Copilot CLI.
//
//go:embed scripts/copilot-guard.sh
var CopilotScript []byte

// GeminiScript is the BeforeTool hook script for Gemini CLI.
//
//go:embed scripts/gemini-guard.sh
var GeminiScript []byte

// OpenCodeScript is the TypeScript plugin for OpenCode.
//
//go:embed scripts/opencode-guard.ts
var OpenCodeScript []byte
