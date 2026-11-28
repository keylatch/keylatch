package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
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

func TestApproveAbortsWhenThePendingValueChangesDuringThePrompt(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	caSetLLMSession(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	testutil.ClearLLMSessionEnv(t)

	// While the approver reads the summary, the agent swaps the pending value.
	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) {
		ctx := audit.WithEmitter(context.Background(), discardAudit{})
		path := customsecret.PendingPath("acme")
		require.NoError(t, vault.Set(ctx, path, []byte("swapped-0123456789"), backendMeta(path), f.cfg, f.env))
		return []byte(testApproverPassphrase), nil
	}
	t.Cleanup(func() { promptHiddenFn = prev })

	_, _, err = caRun(t, nil, "secret", "approve", "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changed while the passphrase prompt was open")
	assert.Equal(t, exitcode.SecurityBlock, caExitCode(err))
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")), "nothing was activated")
	e, _ := customsecret.Find(paths.CustomSecrets(llmcontext.DefaultLookup), "acme")
	assert.False(t, e.Active())
}

func TestApproveAbortsWhenTheRulesChangeDuringThePrompt(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	caSetLLMSession(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	testutil.ClearLLMSessionEnv(t)
	file := paths.CustomSecrets(llmcontext.DefaultLookup)

	prev := promptHiddenFn
	promptHiddenFn = func() ([]byte, error) {
		e, err := customsecret.Find(file, "acme")
		require.NoError(t, err)
		e.Proposed.Hosts = []string{"api.evil.example"}
		require.NoError(t, customsecret.Replace(file, e))
		return []byte(testApproverPassphrase), nil
	}
	t.Cleanup(func() { promptHiddenFn = prev })

	_, _, err = caRun(t, nil, "secret", "approve", "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changed while the passphrase prompt was open")
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")))
}

func TestRejectWorksOnAnInvalidProposalButApproveDoesNot(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	bad := customsecret.Secret{Name: "acme", Hosts: []string{"127.0.0.1"}, Paths: []string{"/"}, Injection: customsecret.Injection{Kind: "query", Name: "k"}}
	require.NoError(t, customsecret.Add(file, customsecret.Secret{
		Name: "acme", Status: customsecret.StatusPending, CreatedAt: time.Now(), Proposed: &bad,
	}))

	_, _, err := caRun(t, nil, "secret", "approve", "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")

	_, errOut, err := caRun(t, nil, "secret", "reject", "acme")
	require.NoError(t, err, errOut)
	_, err = customsecret.Find(file, "acme")
	assert.ErrorIs(t, err, customsecret.ErrNotFound)
	_ = f
}

func TestApprovalPromptListsEveryHostAndTheBaseURLEnv(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	caSetLLMSession(t)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), "secret", "add", "acme", "--value-stdin",
		"--host", "api.acme.example", "--host", "eu.acme.example", "--basic", "svc-user\u0009x",
		"--base-url-env", "ACME_BASE_URL")
	require.Error(t, err, "a control character in the basic user is refused")
	_ = errOut

	_, errOut, err = caRun(t, caStdinFile(t, secretTestValue), "secret", "add", "acme", "--value-stdin",
		"--host", "api.acme.example", "--host", "eu.acme.example", "--basic", "svc-user", "--base-url-env", "ACME_BASE_URL")
	require.NoError(t, err, errOut)
	testutil.ClearLLMSessionEnv(t)

	_, errOut, err = caRun(t, nil, "secret", "approve", "acme")
	require.NoError(t, err, errOut)
	for _, want := range []string{"api.acme.example", "eu.acme.example", "ACME_BASE_URL", "svc-user", fmt.Sprintf("stored value, %d bytes", len(secretTestValue))} {
		assert.Contains(t, errOut, want)
	}
	assert.NotContains(t, errOut, secretTestValue)

	out, _, err := caRun(t, nil, "secret", "show", "acme")
	require.NoError(t, err)
	assert.Contains(t, out, "/sdk/acme/v1/<path>")
	assert.Contains(t, out, "/sdk/acme/h/eu.acme.example/<path>")
}

func TestHumanAddWithoutATerminalBecomesPending(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	interactiveStdin = func() bool { return false }

	out, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "secret proposed")
	assert.Contains(t, out, "stdin is not a terminal")
	e, _ := customsecret.Find(paths.CustomSecrets(llmcontext.DefaultLookup), "acme")
	assert.False(t, e.Active())
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")))
}

func TestHumanAddWithoutAnApproverPassphraseBecomesPending(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	prev := interactiveStdin
	interactiveStdin = func() bool { return true }
	t.Cleanup(func() { interactiveStdin = prev })

	out, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "approve init")
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")))
}

func TestWrongPassphraseOnAddWritesNothing(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	withHiddenAnswers(t, "wrong passphrase")

	_, _, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.Error(t, err)
	_, statErr := os.Stat(paths.CustomSecrets(llmcontext.DefaultLookup))
	assert.True(t, os.IsNotExist(statErr))
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")))
}

func TestCorruptRulesFileLeavesTheExistingValueIntact(t *testing.T) {
	f := secretFixture(t)
	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	_, errOut, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)
	require.NoError(t, os.WriteFile(file, []byte("{corrupt"), 0o600))

	// A replace and an add of another name both abort before any write.
	_, _, err = caRun(t, caStdinFile(t, "replacement-0123456789"), secretAddArgs("--replace", "--value-stdin")...)
	require.Error(t, err)
	_, _, err = caRun(t, caStdinFile(t, "other-0123456789"), "secret", "add", "other", "--value-stdin", "--host", "api.other.example", "--query", "k")
	require.Error(t, err)

	got, err := storedValue(t, f, "acme")
	require.NoError(t, err)
	assert.Equal(t, secretTestValue, string(got), "the existing value is untouched")
	assert.False(t, valueExists(t, f, customsecret.ValuePath("other")), "nothing was written for the other name")
	raw, _ := os.ReadFile(file)
	assert.Equal(t, "{corrupt", string(raw), "the corrupt file is not overwritten")
}

func TestAddWaitsForTheRulesLock(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	caSetLLMSession(t)

	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = customsecret.WithLock(file, func(customsecret.Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	done := make(chan error, 1)
	go func() {
		_, _, err := caRun(t, caStdinFile(t, secretTestValue), secretAddArgs("--value-stdin")...)
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("add finished while another process held the lock")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("add did not resume after the lock was released")
	}
	e, err := customsecret.Find(file, "acme")
	require.NoError(t, err)
	assert.False(t, e.Active())
	assert.True(t, slices.Equal(e.Proposed.Hosts, []string{"api.acme.example"}))
}

func backendMeta(path string) backend.Meta {
	return backend.Meta{Path: path, Backend: "file", Version: 1}
}

func TestApproveAcceptsANonCanonicalStoredProposal(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	t.Cleanup(func() { _ = registry.InitFromConfig(context.Background(), llmcontext.DefaultLookup) })
	file := paths.CustomSecrets(llmcontext.DefaultLookup)

	// A proposal as an older build or a hand edit could have stored it: not yet canonical.
	proposal := customsecret.Secret{
		Name: "acme", Hosts: []string{"API.Acme.example"}, Paths: []string{"/v1/"}, Methods: []string{"get"},
		Injection: customsecret.Injection{Kind: customsecret.InjectQuery, Name: "k"},
	}
	require.NoError(t, customsecret.Add(file, customsecret.Secret{
		Name: "acme", Status: customsecret.StatusPending, CreatedAt: time.Now(), Proposed: &proposal,
	}))

	_, errOut, err := caRun(t, nil, "secret", "approve", "acme")
	require.NoError(t, err, errOut)
	e, err := customsecret.Find(file, "acme")
	require.NoError(t, err)
	assert.True(t, e.Active())
	assert.Equal(t, []string{"api.acme.example"}, e.Hosts, "the activated rules are canonical")
	assert.Equal(t, []string{"/v1"}, e.Paths)
	assert.Equal(t, []string{"GET"}, e.Methods)
}

func TestFailedProposalPutsThePreviousPendingValueBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	secretApprover(t, f)
	rules := filepath.Join(t.TempDir(), "rules")
	t.Setenv("KEYLATCH_CUSTOM_SECRETS_PATH", filepath.Join(rules, "custom-secrets.json"))
	caSetLLMSession(t)

	const first, second = "first-pending-0123456789", "second-pending-0123456789"
	_, errOut, err := caRun(t, caStdinFile(t, first), secretAddArgs("--value-stdin")...)
	require.NoError(t, err, errOut)

	// Saving the second proposal fails: a read-only rules file blocks the rename on
	// Windows, an unwritable rules directory elsewhere.
	block, blocked, unblock := rules, os.FileMode(0o500), os.FileMode(0o700)
	if runtime.GOOS == "windows" {
		block, blocked, unblock = filepath.Join(rules, "custom-secrets.json"), 0o400, 0o600
	}
	require.NoError(t, os.Chmod(block, blocked))
	t.Cleanup(func() { _ = os.Chmod(block, unblock) })
	_, _, err = caRun(t, caStdinFile(t, second), secretAddArgs("--replace", "--value-stdin")...)
	require.Error(t, err)

	ctx := audit.WithEmitter(context.Background(), discardAudit{})
	got, err := vault.Get(ctx, customsecret.PendingPath("acme"), f.cfg, f.env)
	require.NoError(t, err)
	assert.Equal(t, first, string(got), "the first proposal's value is back")
}

func TestShortValueIsRefused(t *testing.T) {
	f := secretFixture(t)
	_, _, err := caRun(t, caStdinFile(t, "short"), secretAddArgs("--value-stdin")...)
	require.Error(t, err)
	assert.False(t, valueExists(t, f, customsecret.ValuePath("acme")))
}

func TestMoreThanSixteenHostsAreRefused(t *testing.T) {
	_ = secretFixture(t)
	args := []string{"secret", "add", "acme", "--value-stdin", "--query", "k"}
	for i := 0; i < 17; i++ {
		args = append(args, "--host", fmt.Sprintf("h%02d.acme.example", i))
	}
	_, _, err := caRun(t, caStdinFile(t, secretTestValue), args...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most 16 hosts")
}
