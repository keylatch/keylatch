package agentsnippet

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/connections"
)

// agentPreset describes the target files and merge strategy for a specific AI agent.
type agentPreset struct {
	name           string
	files          []ProfileFile
	conflictPolicy string //nolint:unused // planned: used by merge logic in Phase 8 profile conflict resolution
}

// agentPresets maps agent names to their target file configurations.
var agentPresets = map[string]agentPreset{
	"claude-code": {
		name: "Claude Code",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.claude/settings.json",
				Mode:           0o600,
				Content:        `{"mcpServers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}`,
				ConflictPolicy: "merge",
			},
		},
	},
	"codex": {
		name: "OpenAI Codex",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.codex/config.json",
				Mode:           0o600,
				Content:        `{"mcpServers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}`,
				ConflictPolicy: "merge",
			},
		},
	},
	"cursor": {
		name: "Cursor",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.cursor/settings.json",
				Mode:           0o600,
				Content:        `{"mcpServers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}`,
				ConflictPolicy: "merge",
			},
		},
	},
	"openhands": {
		name: "OpenHands",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.openhands/config.json",
				Mode:           0o600,
				Content:        `{"mcp":{"servers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}}`,
				ConflictPolicy: "merge",
			},
		},
	},
	"opencode": {
		name: "OpenCode",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.opencode/config.json",
				Mode:           0o600,
				Content:        `{"mcpServers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}`,
				ConflictPolicy: "merge",
			},
		},
	},
	"openclaw": {
		name: "OpenClaw",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.openclaw/config.json",
				Mode:           0o600,
				Content:        `{"mcpServers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}`,
				ConflictPolicy: "merge",
			},
		},
	},
	"nanoclaw": {
		name: "NanoClaw",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.nanoclaw/config.json",
				Mode:           0o600,
				Content:        `{"mcpServers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}`,
				ConflictPolicy: "merge",
			},
		},
	},
	"hermes": {
		name: "Hermes",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.hermes/config.json",
				Mode:           0o600,
				Content:        `{"mcpServers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}`,
				ConflictPolicy: "merge",
			},
		},
	},
	"n8n": {
		name: "n8n",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.n8n/keylatch.env",
				Mode:           0o600,
				Content:        "KEYLATCH_NAMESPACE=${KEYLATCH_NAMESPACE:-default}\nKEYLATCH_LOG_LEVEL=${KEYLATCH_LOG_LEVEL:-info}\n",
				ConflictPolicy: "overwrite",
			},
		},
	},
	"dify": {
		name: "Dify",
		files: []ProfileFile{
			{
				Path:           "${HOME}/.dify/keylatch.env",
				Mode:           0o600,
				Content:        "KEYLATCH_NAMESPACE=${KEYLATCH_NAMESPACE:-default}\nKEYLATCH_LOG_LEVEL=${KEYLATCH_LOG_LEVEL:-info}\n",
				ConflictPolicy: "overwrite",
			},
		},
	},
	"custom": {
		name: "Custom Agent",
		files: []ProfileFile{
			{
				Path:           "${CONFIG_PATH}",
				Mode:           0o600,
				Content:        `{"mcpServers":{"keylatch":{"command":"keylatch","args":["mcp","--stdio"]}}}`,
				ConflictPolicy: "create_only",
			},
		},
	},
}

// GenerateProfile generates a per-agent profile for the given agent and mode.
//
// Security invariants:
//   - S3-8: profile files contain placeholder values only — no actual secret bytes
//   - S3-16(a): no KEYLATCH_MCP_TOKEN in any written config file for stdio mode
func GenerateProfile(ctx context.Context, agent string, mode ProfileMode, store connections.Store) (Profile, error) {
	preset, ok := agentPresets[agent]
	if !ok {
		return Profile{}, fmt.Errorf("agentsnippet: unknown agent preset %q", agent)
	}

	// Verify no file content contains actual secrets.
	for _, f := range preset.files {
		if err := assertProfileFileNoSecrets(f); err != nil {
			return Profile{}, err
		}
	}

	// Generate instructions.
	instructions, err := GenerateInstruction(ctx, InstructionOpts{
		AgentName:  agent,
		IncludeMCP: mode == ProfileModeMCP,
	}, store)
	if err != nil {
		return Profile{}, fmt.Errorf("agentsnippet: generate instruction: %w", err)
	}

	healthCheck := "keylatch status"
	rollback := fmt.Sprintf("To reverse the keylatch %s setup:\n"+
		"1. Remove the 'keylatch' entry from mcpServers in your agent config.\n"+
		"2. Run `keylatch agent setup %s --dry-run` to verify the proposed changes before reapplying.", agent, agent)

	return Profile{
		Agent:        agent,
		Mode:         mode,
		Files:        preset.files,
		Instructions: instructions,
		HealthCheck:  healthCheck,
		Rollback:     rollback,
	}, nil
}

// assertProfileFileNoSecrets verifies that a ProfileFile.Content contains only
// placeholder values, not actual secret bytes.
//
// S3-8: profile files must contain placeholders (${KEYLATCH_*} or <REPLACE_ME>),
// never actual secret values.
func assertProfileFileNoSecrets(f ProfileFile) error {
	// Forbidden patterns.
	for _, pattern := range leakPatterns {
		if pattern.MatchString(f.Content) {
			return &ErrSnippetLeakDetected{
				Reason: fmt.Sprintf("profile file %q contains forbidden pattern: %s", f.Path, pattern.String()),
			}
		}
	}
	return nil
}
