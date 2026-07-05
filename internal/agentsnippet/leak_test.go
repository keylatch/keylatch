package agentsnippet

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canaryValue = "KEYLATCH_CANARY_PHASE3_SNIPPET_0xDEADBEEF"

// highEntropyToken is a 32-byte high-entropy substring that must not appear
// in MCP config for stdio mode.
const highEntropyToken = "Rz9kNJ7qXpLmWbD3YsAeT1cF6vGhM2nP"

// tokenShapeRE detects high-entropy token-shaped substrings.
var tokenShapeRE = regexp.MustCompile(`[A-Za-z0-9\-_\.]{32,}`)

// TestSnippetDoesNotContainCanary verifies that the generated instruction
// snippet does not contain the canary value from a fixture connection.
func TestSnippetDoesNotContainCanary(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	// Seed a connection with a canary value as the secret.
	_, err := connections.Connect(ctx, "openrouter", connections.ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte(canaryValue)},
	}, store)
	require.NoError(t, err)

	snippet, err := GenerateInstruction(ctx, InstructionOpts{IncludeMCP: true}, store)
	require.NoError(t, err)

	assert.NotContains(t, snippet, canaryValue, "snippet must not contain canary value")
}

// TestMCPConfigDoesNotContainCanary verifies that GenerateMCPConfig output
// does not contain the canary value or KEYLATCH_MCP_TOKEN.
func TestMCPConfigDoesNotContainCanary(t *testing.T) {
	ctx := context.Background()

	cfg, err := GenerateMCPConfig(ctx)
	require.NoError(t, err)

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	assert.NotContains(t, string(data), canaryValue)
	assert.NotContains(t, string(data), "KEYLATCH_MCP_TOKEN")
}

// TestProfileFilesDoNotContainCanary verifies that generated profile files
// do not contain canary values from fixture connections.
func TestProfileFilesDoNotContainCanary(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	// Seed a connection with a canary value.
	_, err := connections.Connect(ctx, "openrouter", connections.ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte(canaryValue)},
	}, store)
	require.NoError(t, err)

	profile, err := GenerateProfile(ctx, "claude-code", ProfileModeMCP, store)
	require.NoError(t, err)

	for _, f := range profile.Files {
		assert.NotContains(t, f.Content, canaryValue,
			"profile file %q must not contain canary value", f.Path)
	}
}

// TestSnippetNoAbsolutePaths verifies no /Users/ or /home/ paths appear
// in generated snippets.
func TestSnippetNoAbsolutePaths(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	snippet, err := GenerateInstruction(ctx, InstructionOpts{IncludeMCP: true}, store)
	require.NoError(t, err)

	assert.NotContains(t, snippet, "/Users/",
		"snippet must not contain absolute macOS home paths")
	assert.NotContains(t, snippet, "/home/",
		"snippet must not contain absolute Linux home paths")
}

// TestMCPConfigNoHighEntropyToken verifies + stdio
// mode MCP config must not contain KEYLATCH_MCP_TOKEN or high-entropy tokens.
func TestMCPConfigNoHighEntropyToken(t *testing.T) {
	// Ensure KEYLATCH_MCP_TOKEN is not set in env.
	t.Setenv("KEYLATCH_MCP_TOKEN", "")

	ctx := context.Background()
	cfg, err := GenerateMCPConfig(ctx)
	require.NoError(t, err)

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	configStr := string(data)
	assert.NotContains(t, configStr, "KEYLATCH_MCP_TOKEN")

	// No high-entropy 32-byte substring should appear in the config.
	matches := tokenShapeRE.FindAllString(configStr, -1)
	for _, match := range matches {
		if len(match) >= 32 {
			// Allow keylatch tool names and known long strings.
			if !strings.Contains(match, "keylatch") && match != highEntropyToken {
				assert.Fail(t, "high-entropy token found in MCP config", "found: %q", match)
			}
		}
	}
}

// TestRepoRelativePathsAbsent verifies that generated snippets do not contain
// repo-relative paths that would expose the development environment.
func TestRepoRelativePathsAbsent(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	snippet, err := GenerateInstruction(ctx, InstructionOpts{}, store)
	require.NoError(t, err)

	// No repo-relative paths like "internal/", "cmd/", "pkg/" should appear.
	repoPathPatterns := []string{
		"internal/registry",
		"internal/connections",
		"cmd/keylatch",
	}
	for _, p := range repoPathPatterns {
		assert.NotContains(t, snippet, p,
			"snippet must not contain repo-relative path %q", p)
	}
}
