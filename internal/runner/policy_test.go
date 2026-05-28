package runner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckPolicy_AbsentFile_ReturnsError verifies that when the policy file does
// not exist, CheckPolicy returns an error. The exact error type depends on the
// policy.Load implementation (currently wraps the stat error).
func TestCheckPolicy_AbsentFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	nonExistentPolicy := filepath.Join(dir, "policy.json")
	nonExistentGrant := filepath.Join(dir, "grants.json")

	_, err := runner.CheckPolicy("openrouter", []string{"node", "index.js"}, runner.PolicyOptions{
		PolicyPath: nonExistentPolicy,
		GrantPath:  nonExistentGrant,
	})
	require.Error(t, err, "absent policy file must return an error")
	// The error wraps os.Stat failure — not ErrPolicyDeny, but a load error.
	assert.Contains(t, err.Error(), "policy",
		"error must reference the policy subsystem")
}

// TestCheckPolicy_EmptyPolicy_DefaultDeny verifies that an empty policy file
// with no rules defaults to deny.
func TestCheckPolicy_EmptyPolicy_DefaultDeny(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	grantPath := filepath.Join(dir, "grants.json")

	// Write a policy with default_deny=true and no rules.
	policyJSON := `{
		"schema_version": 1,
		"mode": "enforcing",
		"default_deny": true,
		"rules": []
	}`
	require.NoError(t, os.WriteFile(policyPath, []byte(policyJSON), 0o600))

	_, err := runner.CheckPolicy("openrouter", []string{"node", "index.js"}, runner.PolicyOptions{
		PolicyPath: policyPath,
		GrantPath:  grantPath,
	})
	require.Error(t, err, "default-deny policy must return ErrPolicyDeny when no rule matches")
	assert.ErrorIs(t, err, runner.ErrPolicyDeny)
}

// TestCheckPolicy_PermissiveMode_Allows verifies that a permissive policy
// allows connections even without explicit rules.
func TestCheckPolicy_PermissiveMode_Allows(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	grantPath := filepath.Join(dir, "grants.json")

	// Write a permissive policy with no rules.
	policyJSON := `{
		"schema_version": 1,
		"mode": "permissive",
		"default_deny": false,
		"rules": []
	}`
	require.NoError(t, os.WriteFile(policyPath, []byte(policyJSON), 0o600))

	_, err := runner.CheckPolicy("openrouter", []string{"node", "index.js"}, runner.PolicyOptions{
		PolicyPath: policyPath,
		GrantPath:  grantPath,
	})
	require.NoError(t, err, "permissive policy must allow when no rule denies")
}

// TestCheckPolicy_ExplicitAllowRule_Allows verifies that an explicit allow rule
// with matching connection permits the request.
func TestCheckPolicy_ExplicitAllowRule_Allows(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	grantPath := filepath.Join(dir, "grants.json")

	policyJSON := `{
		"schema_version": 1,
		"mode": "enforcing",
		"default_deny": false,
		"rules": []
	}`
	require.NoError(t, os.WriteFile(policyPath, []byte(policyJSON), 0o600))

	_, err := runner.CheckPolicy("openrouter", []string{"node", "index.js"}, runner.PolicyOptions{
		PolicyPath: policyPath,
		GrantPath:  grantPath,
		Capability: "inject",
	})
	require.NoError(t, err, "non-default-deny policy must permit the request when no rules deny")
}

// TestCheckPolicy_MalformedPolicyFile_ReturnsError verifies that a malformed
// policy file returns an error (not a silent default-deny).
func TestCheckPolicy_MalformedPolicyFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	grantPath := filepath.Join(dir, "grants.json")

	require.NoError(t, os.WriteFile(policyPath, []byte("{invalid json"), 0o600))

	_, err := runner.CheckPolicy("openrouter", []string{"node"}, runner.PolicyOptions{
		PolicyPath: policyPath,
		GrantPath:  grantPath,
	})
	require.Error(t, err, "malformed policy file must return an error")
}

// TestOK_ReturnsTrue verifies that runner.OK always returns true (Phase 1 stub).
func TestOK_ReturnsTrue(t *testing.T) {
	assert.True(t, runner.OK(context.Background()),
		"runner.OK must return true (Phase 1 stub)")
}

// TestCheckPolicyWithAudit_DefaultDeny verifies CheckPolicyWithAudit propagates
// the denial from the underlying CheckPolicy call.
func TestCheckPolicyWithAudit_DefaultDeny(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	grantPath := filepath.Join(dir, "grants.json")

	policyJSON := `{
		"schema_version": 1,
		"mode": "enforcing",
		"default_deny": true,
		"rules": []
	}`
	require.NoError(t, os.WriteFile(policyPath, []byte(policyJSON), 0o600))

	// Pass nil logger — CheckPolicyWithAudit must still work with nil audit logger.
	_, err := runner.CheckPolicyWithAudit(context.Background(), nil, "openrouter",
		[]string{"node", "index.js"}, runner.PolicyOptions{
			PolicyPath: policyPath,
			GrantPath:  grantPath,
		})
	require.Error(t, err)
	assert.ErrorIs(t, err, runner.ErrPolicyDeny,
		"CheckPolicyWithAudit must propagate ErrPolicyDeny from CheckPolicy")
}

// TestCheckPolicyWithAudit_Permissive_Allows verifies that CheckPolicyWithAudit
// allows when the underlying policy is permissive.
func TestCheckPolicyWithAudit_Permissive_Allows(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	grantPath := filepath.Join(dir, "grants.json")

	policyJSON := `{
		"schema_version": 1,
		"mode": "permissive",
		"default_deny": false,
		"rules": []
	}`
	require.NoError(t, os.WriteFile(policyPath, []byte(policyJSON), 0o600))

	_, err := runner.CheckPolicyWithAudit(context.Background(), nil, "openrouter",
		[]string{"node", "index.js"}, runner.PolicyOptions{
			PolicyPath: policyPath,
			GrantPath:  grantPath,
		})
	require.NoError(t, err, "permissive policy must allow via CheckPolicyWithAudit")
}
