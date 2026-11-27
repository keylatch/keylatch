package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/customsecret"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretApprover configures an approver passphrase in the fixture's config dir
// and makes stdin look like a terminal.
func secretApprover(t *testing.T, f *caFixture) {
	t.Helper()
	withCheapApproverKDF(t)
	key, _, err := approval.NewApproverKey([]byte(testApproverPassphrase), approverKDFParams)
	require.NoError(t, err)
	require.NoError(t, approval.SaveApproverKey(filepath.Join(f.configDir, "approver.json"), key))
	withHiddenAnswers(t, testApproverPassphrase)
	prev := interactiveStdin
	interactiveStdin = func() bool { return true }
	t.Cleanup(func() { interactiveStdin = prev })
}

func valueExists(t *testing.T, f *caFixture, path string) bool {
	t.Helper()
	ctx := audit.WithEmitter(context.Background(), discardAudit{})
	_, err := vault.Get(ctx, path, f.cfg, f.env)
	return err == nil
}

// routed reports whether a fresh registry load would serve the secret.
func routed(t *testing.T, name string) bool {
	t.Helper()
	require.NoError(t, registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup))
	registerCustomSecrets(llmcontext.DefaultLookup)
	_, err := registry.Get(name)
	return err == nil
}

func TestAgentAddStaysPendingUntilApproved(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	t.Cleanup(func() { _ = registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup) })
	file := paths.CustomSecrets(llmcontext.DefaultLookup)

	caSetLLMSession(t)
	out, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "secret proposed")
	assert.Contains(t, out, "pending owner approval")
	assert.NotContains(t, out+errOut, secretTestValue)

	e, err := customsecret.Find(file, "acme")
	require.NoError(t, err)
	assert.False(t, e.Active())
	assert.False(t, routed(t, "acme"), "a pending secret is never routed")
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")), "the gateway's path holds nothing")
	assert.True(t, valueExists(t, f, customsecret.PendingPath("acme")))

	for _, args := range [][]string{{"secret", "list"}, {"secret", "list", "--json"}, {"secret", "show", "acme"}, {"status"}} {
		o, e2, err := caRun(t, nil, args...)
		require.NoError(t, err, args)
		assert.Contains(t, o, "acme", args)
		assert.NotContains(t, o+e2, secretTestValue, args)
	}
	o, _, _ := caRun(t, nil, "secret", "list")
	assert.Contains(t, o, "pending approval")

	for _, args := range [][]string{{"secret", "approve", "acme"}, {"secret", "reject", "acme"}, {"secret", "rm", "acme", "--force"}} {
		_, _, err := caRun(t, nil, args...)
		require.Error(t, err, args)
		assert.Equal(t, exitcode.SecurityBlock, caExitCode(err), args)
	}
	assert.False(t, routed(t, "acme"))

	testutil.ClearLLMSessionEnv(t)
	out, errOut, err = caRun(t, nil, "secret", "approve", "acme")
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "secret approved")
	for _, want := range []string{"api.acme.example", "/v1", "GET", "Authorization", "stored value"} {
		assert.Contains(t, errOut, want)
	}
	assert.NotContains(t, out+errOut, secretTestValue)
	assert.True(t, routed(t, "acme"))
	got, err := storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, secretTestValue, string(got))
	assert.False(t, valueExists(t, f, customsecret.PendingPath("acme")), "the pending value moved")
	e, _ = customsecret.Find(file, "acme")
	assert.True(t, e.Active())
	assert.Nil(t, e.Proposed)

	_, _, err = caRun(t, nil, "secret", "approve", "acme")
	assert.Error(t, err, "nothing left to approve")
}

func TestAgentReferenceProposalShowsTheReferenceOnApprove(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	caSetLLMSession(t)
	_, errOut, err := caRun(t, nil, "secret", "add", "acme", "--ref", "op://Private/acme/key", "--host", "api.acme.example", "--query", "k")
	require.NoError(t, err, errOut)

	testutil.ClearLLMSessionEnv(t)
	_, errOut, err = caRun(t, nil, "secret", "approve", "acme")
	require.NoError(t, err, errOut)
	assert.Contains(t, errOut, "reference op://Private/acme/key")
	got, err := storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, "op://Private/acme/key", string(got))
}

func TestRejectRemovesPendingSecretAndValue(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	t.Cleanup(func() { _ = registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup) })
	caSetLLMSession(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)

	testutil.ClearLLMSessionEnv(t)
	out, errOut, err := caRun(t, nil, "secret", "reject", "acme")
	require.NoError(t, err, errOut)
	assert.NotContains(t, out+errOut, secretTestValue)
	_, err = customsecret.Find(paths.CustomSecrets(llmcontext.DefaultLookup), "acme")
	assert.ErrorIs(t, err, customsecret.ErrNotFound)
	assert.False(t, valueExists(t, f, customsecret.PendingPath("acme")))
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")))
	assert.False(t, routed(t, "acme"))
}

func TestApproveNeedsTheApproverPassphrase(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	caSetLLMSession(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)

	testutil.ClearLLMSessionEnv(t)
	withHiddenAnswers(t, "wrong passphrase")
	_, _, err = caRun(t, nil, "secret", "approve", "acme")
	require.Error(t, err)
	e, _ := customsecret.Find(paths.CustomSecrets(llmcontext.DefaultLookup), "acme")
	assert.False(t, e.Active(), "a wrong passphrase activates nothing")
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")))
}

func TestPendingReplaceLeavesTheActiveSecretUntouched(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	t.Cleanup(func() { _ = registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup) })
	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	before, _ := customsecret.Find(file, "acme")

	const proposed = "agent-proposed-0123456789"
	caSetLLMSession(t)
	out, errOut, err := caRun(t, caStdinFile(t, proposed), "secret", "add", "acme", "--replace", "--value-stdin",
		"--host", "api.evil.example", "--query", "k")
	require.NoError(t, err, errOut)
	assert.NotContains(t, out+errOut, proposed)

	e, _ := customsecret.Find(file, "acme")
	assert.Equal(t, before.Hosts, e.Hosts, "active rules unchanged")
	assert.Equal(t, before.Injection, e.Injection)
	require.NotNil(t, e.Proposed)
	assert.Equal(t, []string{"api.evil.example"}, e.Proposed.Hosts)
	got, err := storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, secretTestValue, string(got), "the active value still serves")
	assert.True(t, routed(t, "acme"))
	reg, _ := registry.Get("acme")
	assert.Equal(t, []string{"api.acme.example"}, reg.Custom.Hosts)
	o, _, _ := caRun(t, nil, "secret", "list")
	assert.Contains(t, o, "active, change pending")

	testutil.ClearLLMSessionEnv(t)
	_, errOut, err = caRun(t, nil, "secret", "reject", "acme")
	require.NoError(t, err, errOut)
	e, _ = customsecret.Find(file, "acme")
	assert.Nil(t, e.Proposed)
	assert.False(t, valueExists(t, f, customsecret.PendingPath("acme")))
	got, _ = storedValue(t, f, "acme")
	assert.Equal(t, secretTestValue, string(got))

	caSetLLMSession(t)
	_, errOut, err = caRun(t, caStdinFile(t, proposed), "secret", "add", "acme", "--replace", "--value-stdin",
		"--host", "api.new.example", "--query", "k")
	require.NoError(t, err, errOut)
	testutil.ClearLLMSessionEnv(t)
	_, errOut, err = caRun(t, nil, "secret", "approve", "acme")
	require.NoError(t, err, errOut)
	e, _ = customsecret.Find(file, "acme")
	assert.Equal(t, []string{"api.new.example"}, e.Hosts)
	got, _ = storedValue(t, f, "acme")
	assert.Equal(t, proposed, string(got))
}
