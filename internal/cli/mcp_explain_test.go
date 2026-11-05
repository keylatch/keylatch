package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/explain"
	keylatchmcp "github.com/keylatch/keylatch/internal/mcp"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/testutil"
)

func TestMCPExplainEvaluatesAsAnAgent(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, policy.Save(path, policy.Policy{
		SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true,
		Rules: []policy.Rule{{ID: "r1", Actor: "llm-session", Connections: []string{"openai"}, Capabilities: []string{"inject"}}},
	}))
	t.Setenv("KEYLATCH_POLICY_PATH", path)

	out, err := mcpExplain(context.Background(), keylatchmcp.ExplainRequest{Connection: "openai", Command: []string{"pnpm", "test"}, Tier: "d2"})
	require.NoError(t, err)
	rep, ok := out.(explain.Report)
	require.True(t, ok)
	assert.Equal(t, explain.CallerAgent, rep.Request.CallerKind)
	assert.Equal(t, "mcp", rep.Request.Actor)
	assert.NotEmpty(t, rep.Request.CWD, "an empty working directory defaults to the server's")
	data, err := json.Marshal(rep)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "pnpm test", "the report never echoes argv")
}

func TestMCPExplainReportsAnUnreadablePolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
	t.Setenv("KEYLATCH_POLICY_PATH", path)

	_, err := mcpExplain(context.Background(), keylatchmcp.ExplainRequest{Connection: "openai", Command: []string{"x"}})
	require.Error(t, err)
}
