package agentsnippet

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/keylatch/keylatch/internal/connections"
)

// leakPatterns is a list of patterns that must not appear in generated snippets.
var leakPatterns = []*regexp.Regexp{
	regexp.MustCompile(`KEYLATCH_MCP_TOKEN`),
	regexp.MustCompile(`/Users/[^/\s]+`), // macOS home paths
	regexp.MustCompile(`/home/[^/\s]+`),  // Linux home paths
}

// GenerateInstruction generates the canonical prose instruction snippet for
// an AI agent to interact with keylatch.
//
// Security invariants:
// - no secret bytes, no $HOME//Users/ paths, no KEYLATCH_MCP_TOKEN
// - appends Limitations section warning about redaction
// - no raw provider-root runtime recommendation
func GenerateInstruction(ctx context.Context, opts InstructionOpts, store connections.Store) (string, error) {
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	maxConn := opts.MaxConnections
	if maxConn <= 0 {
		maxConn = 50
	}

	// Collect current connection names from vault.
	statuses, err := connections.Status(ctx, connections.StatusOptions{Namespace: opts.Namespace}, store)
	if err != nil {
		return "", fmt.Errorf("agentsnippet: list connections: %w", err)
	}

	// Collect provider slugs, sorted, up to maxConn.
	providers := make([]string, 0, len(statuses))
	for _, s := range statuses {
		providers = append(providers, s.Connection.Provider)
	}
	sort.Strings(providers)
	if len(providers) > maxConn {
		providers = providers[:maxConn]
	}

	connList := "none configured"
	if len(providers) > 0 {
		connList = strings.Join(providers, ", ")
	}

	var sb strings.Builder

	// Canonical prose template (spec §3 snippet).
	sb.WriteString("# Keylatch Integration\n\n")
	sb.WriteString("You are working in an environment managed by **Keylatch**, a zero-trust credential vault.\n\n")
	sb.WriteString("## How to use credentials\n\n")
	fmt.Fprintf(&sb, "Available connections: %s\n\n", connList)
	sb.WriteString("To run a command with credentials injected:\n")
	sb.WriteString("```\nkeylatch run <connection> -- <your-command>\n```\n\n")
	sb.WriteString("To test a connection:\n")
	sb.WriteString("```\nkeylatch test <connection>\n```\n\n")
	sb.WriteString("To list all connections:\n")
	sb.WriteString("```\nkeylatch list\n```\n\n")

	// MCP tool inventory block (spec §3 second snippet).
	if opts.IncludeMCP {
		sb.WriteString("## MCP Tools\n\n")
		sb.WriteString("The following MCP tools are available through the keylatch MCP server:\n\n")
		sb.WriteString("- `keylatch_status` — list all connections with health status\n")
		sb.WriteString("- `keylatch_list_connections` — list provider/account/namespace metadata\n")
		sb.WriteString("- `keylatch_describe` — describe a provider template (no secret values)\n")
		sb.WriteString("- `keylatch_test` — test a connection's health\n")
		sb.WriteString("- `keylatch_run` — run a command using a connection's credentials\n\n")
	}

	// Limitations section.
	sb.WriteString("## Limitations\n\n")
	sb.WriteString("**Important**: Keylatch gateway response redaction is best-effort and is NOT a security boundary. ")
	sb.WriteString("Credentials may appear in subprocess output if the subprocess is not governed by a gateway runtime. ")
	sb.WriteString("Do not rely on redaction as a security guarantee — always use the appropriate runtime mode.\n\n")

	result := sb.String()

	// assert no leak patterns.
	if err := assertNoLeaks(result); err != nil {
		return "", err
	}

	// when IncludeMCP is true, no raw provider-root runtime recommendation.
	if opts.IncludeMCP && strings.Contains(result, "direct_run") {
		return "", &ErrSnippetLeakDetected{Reason: "raw provider-root runtime recommendation detected"}
	}

	return result, nil
}

// assertNoLeaks checks that snippet contains no forbidden patterns.
func assertNoLeaks(snippet string) error {
	for _, pattern := range leakPatterns {
		if pattern.MatchString(snippet) {
			return &ErrSnippetLeakDetected{Reason: "pattern matched: " + pattern.String()}
		}
	}
	return nil
}
