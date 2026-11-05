package runner_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/grant"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxAuditLogger(t *testing.T) *audit.Logger {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	salt := make([]byte, 32)
	dek := make([]byte, 32)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(dek)
	l, err := audit.Open(filepath.Join(dir, "audit.log"), salt, dek)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func mxPolicyFile(t *testing.T, body string) (policyPath, grantPath string) {
	t.Helper()
	dir := t.TempDir()
	policyPath = filepath.Join(dir, "policy.json")
	grantPath = filepath.Join(dir, "grants.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(body), 0o600))
	return policyPath, grantPath
}

func mxOnlyEvent(t *testing.T, l *audit.Logger) audit.Event {
	t.Helper()
	events, err := l.Scan(audit.SinceOpts{})
	require.NoError(t, err)
	require.Len(t, events, 1, "exactly one policy_check event per call")
	assert.Equal(t, audit.ActionPolicyCheck, events[0].Action)
	return events[0]
}

func TestCheckPolicyWithAudit_DenyIsAuditedAsDenied(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	pp, gp := mxPolicyFile(t, `{"schema_version":1,"mode":"enforcing","default_deny":true,"rules":[]}`)
	l := mxAuditLogger(t)

	_, err := runner.CheckPolicyWithAudit(context.Background(), l, "openrouter", []string{"node"}, runner.PolicyOptions{
		PolicyPath: pp, GrantPath: gp, Actor: "alice", Runtime: "gateway_typed",
	})
	require.ErrorIs(t, err, runner.ErrPolicyDeny)

	ev := mxOnlyEvent(t, l)
	assert.Equal(t, audit.OutcomeDenied, ev.Outcome)
	assert.Equal(t, "deny", ev.Extra["result"])
	assert.Equal(t, "gateway_typed", ev.RuntimeMode)
}

func TestCheckPolicyWithAudit_ApprovalRuleRecordsRuleID(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	rules := []map[string]any{{
		"id": "needs-ok", "actor": "*", "connections": []string{"openrouter"},
		"capabilities": []string{"inject"}, "approval": true, "created_at": time.Now().UTC(),
	}}
	body, err := json.Marshal(map[string]any{"schema_version": 1, "mode": "enforcing", "default_deny": true, "rules": rules})
	require.NoError(t, err)
	pp, gp := mxPolicyFile(t, string(body))
	l := mxAuditLogger(t)

	d, err := runner.CheckPolicyWithAudit(context.Background(), l, "openrouter", []string{"node"}, runner.PolicyOptions{
		PolicyPath: pp, GrantPath: gp, Actor: "alice",
	})
	require.ErrorIs(t, err, runner.ErrApprovalRequired)
	assert.True(t, d.ApprovalRequired)

	ev := mxOnlyEvent(t, l)
	assert.Equal(t, audit.OutcomeError, ev.Outcome, "approval-required is not a plain success")
	assert.Equal(t, "allow:rule:needs-ok", ev.Extra["result"])
}

func TestCheckPolicyWithAudit_GrantOverridesDeny(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	dir := t.TempDir()
	env := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "KEYLATCH_GRANTS_PATH":
			return filepath.Join(dir, "grants.json")
		case "KEYLATCH_GRANTS_DIR":
			return filepath.Join(dir, "grants")
		case "KEYLATCH_GRANT_ACCESSOR_KEY_PATH":
			return filepath.Join(dir, "grant.key")
		}
		return ""
	}
	g, err := grant.Create(context.Background(), grant.GrantSpec{Actor: "alice", Connection: "openrouter", Capability: "inject", TTL: time.Hour}, env)
	require.NoError(t, err)

	pp := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(pp, []byte(`{"schema_version":1,"mode":"enforcing","default_deny":true,"rules":[]}`), 0o600))
	l := mxAuditLogger(t)

	d, err := runner.CheckPolicyWithAudit(context.Background(), l, "openrouter", []string{"node"}, runner.PolicyOptions{
		PolicyPath: pp, GrantPath: env("KEYLATCH_GRANTS_PATH"), Actor: "alice",
	})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	assert.Equal(t, g.ID, d.MatchedGrantID)

	ev := mxOnlyEvent(t, l)
	assert.Equal(t, audit.OutcomeOK, ev.Outcome)
	assert.Equal(t, "grant:"+g.ID, ev.Extra["result"])

	// A grant for another actor must not override the deny.
	_, err = runner.CheckPolicy("openrouter", []string{"node"}, runner.PolicyOptions{
		PolicyPath: pp, GrantPath: env("KEYLATCH_GRANTS_PATH"), Actor: "mallory",
	})
	assert.ErrorIs(t, err, runner.ErrPolicyDeny)
}

func TestCheckPolicyWithAudit_LoadErrorIsAuditedAsError(t *testing.T) {
	pp, gp := mxPolicyFile(t, "{broken")
	l := mxAuditLogger(t)
	_, err := runner.CheckPolicyWithAudit(context.Background(), l, "openrouter", []string{"node"}, runner.PolicyOptions{PolicyPath: pp, GrantPath: gp})
	require.Error(t, err)
	assert.NotErrorIs(t, err, runner.ErrPolicyDeny)

	ev := mxOnlyEvent(t, l)
	assert.Equal(t, audit.OutcomeError, ev.Outcome)
	assert.Equal(t, "deny", ev.Extra["result"], "a failed load never records an allow")
}

func TestCheckPolicyWithAudit_ClosedLoggerStillReturnsDecision(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	pp, gp := mxPolicyFile(t, `{"schema_version":1,"mode":"enforcing","default_deny":true,"rules":[]}`)
	l := mxAuditLogger(t)
	require.NoError(t, l.Close())
	_, err := runner.CheckPolicyWithAudit(context.Background(), l, "openrouter", []string{"node"}, runner.PolicyOptions{PolicyPath: pp, GrantPath: gp})
	assert.ErrorIs(t, err, runner.ErrPolicyDeny, "audit write failure must not turn a deny into an allow")
}

func TestCheckPolicy_InvalidRuntimeIsDenied(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	pp, gp := mxPolicyFile(t, `{"schema_version":1,"mode":"enforcing","default_deny":false,"rules":[]}`)
	d, err := runner.CheckPolicy("openrouter", []string{"node"}, runner.PolicyOptions{
		PolicyPath: pp, GrantPath: gp, Runtime: "bogus-runtime",
	})
	require.ErrorIs(t, err, runner.ErrPolicyDeny)
	assert.False(t, d.Allow)
}
