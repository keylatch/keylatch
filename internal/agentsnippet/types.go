// Package agentsnippet generates the copy-paste agent instruction prose, MCP
// config JSON, and per-agent profile snippets. It is consumed by the UI
// first-run step (Phase 10), the `keylatch agent snippet` CLI command, and the
// `keylatch agent setup` installer (Epic 05).
package agentsnippet

import "os"

// InstructionOpts configures prose template generation.
type InstructionOpts struct {
	IncludeMCP     bool   // if true, append the MCP tool inventory block
	AgentName      string // optional: name of the target agent
	Namespace      string // vault namespace (defaults to "default")
	MaxConnections int    // max number of connections to include (default 50)
}

// MCPConfig is the top-level MCP server configuration structure.
// Matches the shape expected by Claude Code's mcpServers JSON config.
type MCPConfig struct {
	MCPServers map[string]MCPServerSpec `json:"mcpServers"`
}

// MCPServerSpec describes a single MCP server entry.
// S3-5 / FIND3-010(a): Env must NOT contain KEYLATCH_MCP_TOKEN.
type MCPServerSpec struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	// Env contains non-secret config only (KEYLATCH_NAMESPACE, KEYLATCH_LOG_LEVEL).
	// INVARIANT: this map must never contain "KEYLATCH_MCP_TOKEN".
	Env map[string]string `json:"env,omitempty"`
}

// ProfileMode describes how the agent interacts with keylatch.
type ProfileMode string

const (
	ProfileModeMCP     ProfileMode = "mcp"
	ProfileModeRun     ProfileMode = "run"
	ProfileModeGateway ProfileMode = "gateway"
)

// Profile is the output of GenerateProfile for a specific agent.
type Profile struct {
	Agent        string        `json:"agent"`
	Mode         ProfileMode   `json:"mode"`
	Files        []ProfileFile `json:"files"`
	Instructions string        `json:"instructions"`
	HealthCheck  string        `json:"health_check"`
	Rollback     string        `json:"rollback"`
}

// ProfileFile describes a single file to be written by the agent installer.
type ProfileFile struct {
	Path           string      `json:"path"`
	Mode           os.FileMode `json:"mode"`
	Content        string      `json:"content"`
	ConflictPolicy string      `json:"conflict_policy"` // "create_only" | "merge" | "overwrite"
}

// ErrSnippetLeakDetected is returned when a generated snippet contains
// secret bytes, absolute home paths, or KEYLATCH_MCP_TOKEN.
type ErrSnippetLeakDetected struct {
	Reason string
}

func (e *ErrSnippetLeakDetected) Error() string {
	return "agentsnippet: leak detected: " + e.Reason
}
