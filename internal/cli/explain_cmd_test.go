package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/explain"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/testutil"
)

func runExplain(t *testing.T, args ...string) []byte {
	t.Helper()
	root := cli.NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	require.NoError(t, root.Execute())
	return out.Bytes()
}

func writeExplainPolicy(t *testing.T, p policy.Policy) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, policy.Save(path, p))
	t.Setenv("KEYLATCH_POLICY_PATH", path)
}

func TestExplainRun_JSON(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	writeExplainPolicy(t, policy.Policy{
		SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true,
		Rules: []policy.Rule{{ID: "r1", Actor: "claude-code", Connections: []string{"openai"}, Capabilities: []string{"inject"}}},
	})

	out := runExplain(t, "explain", "--json", "run", "--actor", "claude-code", "openai", "--", "pnpm", "test")
	var rep explain.Report
	require.NoError(t, json.Unmarshal(out, &rep))
	assert.Equal(t, explain.SchemaVersion, rep.SchemaVersion)
	assert.Equal(t, explain.DecisionAllow, rep.Decision)
	require.NotNil(t, rep.Tier)
	assert.Equal(t, "D2", *rep.Tier)
	assert.Equal(t, explain.LocationCaller, rep.ChildLocation)
	assert.Contains(t, rep.Hosts, "api.openai.com")
}

func TestExplainRun_DeniesWithoutRule(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	writeExplainPolicy(t, policy.Policy{SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true})

	out := runExplain(t, "explain", "--json", "run", "--actor", "claude-code", "openai", "--", "pnpm", "test")
	var rep explain.Report
	require.NoError(t, json.Unmarshal(out, &rep))
	assert.Equal(t, explain.DecisionDeny, rep.Decision)
	assert.Nil(t, rep.Tier)
}

func TestExplainRun_MissingPolicyDeniesByDefault(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	t.Setenv("KEYLATCH_POLICY_PATH", filepath.Join(t.TempDir(), "absent.json"))

	out := runExplain(t, "explain", "--json", "run", "--actor", "claude-code", "openai", "--", "ls")
	var rep explain.Report
	require.NoError(t, json.Unmarshal(out, &rep))
	assert.Equal(t, explain.DecisionDeny, rep.Decision)
	assert.True(t, rep.Policy.DefaultDeny)
}

func TestExplainRun_Text(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	writeExplainPolicy(t, policy.Policy{SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: false})

	out := string(runExplain(t, "explain", "run", "--actor", "human-shell", "openai", "--", "ls"))
	assert.Contains(t, out, "decision:     allow")
	assert.Contains(t, out, "D2 gateway_session")
	assert.Contains(t, out, "residual risk:")
}

func TestExplainPolicy_JSON(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	writeExplainPolicy(t, policy.Policy{
		SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true,
		Rules: []policy.Rule{{ID: "r1", Actor: "claude-code", Connections: []string{"openai"}, Capabilities: []string{"inject"}}},
	})

	var rep explain.PolicyReport
	require.NoError(t, json.Unmarshal(runExplain(t, "explain", "--json", "policy"), &rep))
	assert.Equal(t, "policy", rep.Kind)
	assert.Equal(t, 1, rep.Policy.RuleCount)
	assert.NotEmpty(t, rep.Callers)
}

// The report follows connection policy documents, not only the rules file: a
// document that allows humans and denies agents is reflected per caller.
func TestExplainPolicy_ReadsConnectionDocuments(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	writeExplainPolicy(t, policy.Policy{SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true})
	dir := filepath.Join(filepath.Dir(os.Getenv("KEYLATCH_POLICY_PATH")), "policy.d")
	require.NoError(t, (connpolicy.Store{Dir: dir}).Replace(map[string]connpolicy.Document{
		"openai": {
			SchemaVersion: connpolicy.SchemaVersion, Connection: "openai", Default: "deny",
			Callers: map[callerkind.Kind]connpolicy.CallerRule{callerkind.Human: {Allow: true}, callerkind.Agent: {}},
		},
	}))
	t.Cleanup(enforce.SetDefault(nil))

	var rep explain.PolicyReport
	require.NoError(t, json.Unmarshal(runExplain(t, "explain", "--json", "policy", "openai"), &rep))

	status := map[string]map[string]string{}
	for _, cp := range rep.Callers {
		require.Len(t, cp.Connections, 1)
		status[cp.Actor] = map[string]string{}
		for _, ts := range cp.Connections[0].Tiers {
			status[cp.Actor][ts.Tier] = ts.Status
		}
	}
	assert.Equal(t, explain.StatusAllowed, status["human-shell"]["D2"])
	assert.Equal(t, explain.StatusDenied, status["llm-session"]["D2"])
}

func TestExplainSchema_PrintsValidJSON(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal(runExplain(t, "explain", "schema"), &doc))
	assert.Contains(t, doc, "$defs")
}
