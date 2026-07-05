package agentsnippet

import (
	"context"
	"fmt"
	"os"
)

// GenerateMCPConfig generates the MCP configuration JSON for keylatch.
//
// Security invariants:
// - Env must never contain KEYLATCH_MCP_TOKEN
func GenerateMCPConfig(_ context.Context) (MCPConfig, error) {
	env := map[string]string{}

	// Include non-secret config vars only.
	if ns := os.Getenv("KEYLATCH_NAMESPACE"); ns != "" {
		env["KEYLATCH_NAMESPACE"] = ns
	}
	if lvl := os.Getenv("KEYLATCH_LOG_LEVEL"); lvl != "" {
		env["KEYLATCH_LOG_LEVEL"] = lvl
	}

	// assert KEYLATCH_MCP_TOKEN is never included.
	if _, hasToken := env["KEYLATCH_MCP_TOKEN"]; hasToken {
		return MCPConfig{}, &ErrSnippetLeakDetected{Reason: "KEYLATCH_MCP_TOKEN must not appear in MCPConfig.Env"}
	}

	spec := MCPServerSpec{
		Command: "keylatch",
		Args:    []string{"mcp", "--stdio"},
	}
	if len(env) > 0 {
		spec.Env = env
	}

	cfg := MCPConfig{
		MCPServers: map[string]MCPServerSpec{
			"keylatch": spec,
		},
	}

	// Final safety check: KEYLATCH_MCP_TOKEN must not be present.
	if err := assertMCPConfigNoToken(cfg); err != nil {
		return MCPConfig{}, err
	}

	return cfg, nil
}

// assertMCPConfigNoToken verifies that no MCPServerSpec.Env contains KEYLATCH_MCP_TOKEN.
func assertMCPConfigNoToken(cfg MCPConfig) error {
	for serverName, spec := range cfg.MCPServers {
		if _, ok := spec.Env["KEYLATCH_MCP_TOKEN"]; ok {
			return &ErrSnippetLeakDetected{
				Reason: fmt.Sprintf("MCPServer %q: Env contains KEYLATCH_MCP_TOKEN", serverName),
			}
		}
	}
	return nil
}
