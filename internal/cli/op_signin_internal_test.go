package cli

// op_signin_internal_test.go — H5: `op signin`'s guidance-first branches,
// exercised via runOPSignin directly (mocked runner, no real op CLI, no
// real terminal). The final interactive-passthrough branch (real
// os/exec.CommandContext hand-off to `op signin`) is deliberately NOT
// exercised here — it requires a real op binary and a real terminal by
// design; see runOPSignin's doc comment.

import (
	"bytes"
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubAccountListRunner is a minimal opAccountListRunner double.
type stubAccountListRunner struct {
	exitCode int
	err      error
	calls    int
}

func (s *stubAccountListRunner) Run(_ context.Context, _ string, args []string, _ []byte) ([]byte, []byte, int, error) {
	s.calls++
	return nil, nil, s.exitCode, s.err
}

func newSigninTestCmd(t *testing.T) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	cmd := &cobra.Command{Use: "signin"}
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	return cmd, &stdout, &stderr
}

func TestRunOPSignin_ServiceAccountTokenSet_NoOp(t *testing.T) {
	t.Parallel()
	cmd, stdout, _ := newSigninTestCmd(t)
	env := func(k string) string {
		if k == "OP_SERVICE_ACCOUNT_TOKEN" {
			return "canary-service-account-token"
		}
		return ""
	}
	runner := &stubAccountListRunner{}

	err := runOPSignin(context.Background(), cmd, env, runner, "/fake/op", true)
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "no signin needed")
	assert.Equal(t, 0, runner.calls, "account list probe must be skipped when a service-account token is present")
	assert.NotContains(t, stdout.String(), "canary-service-account-token", "token must never be printed")
}

func TestRunOPSignin_OpBinaryMissing_Errors(t *testing.T) {
	t.Parallel()
	cmd, _, stderr := newSigninTestCmd(t)
	env := func(string) string { return "" }
	runner := &stubAccountListRunner{}

	err := runOPSignin(context.Background(), cmd, env, runner, "", true)
	require.Error(t, err)
	assert.Contains(t, stderr.String(), "1Password CLI not available")
	assert.Equal(t, 0, runner.calls)
}

func TestRunOPSignin_AccountListSucceeds_NoSigninNeeded(t *testing.T) {
	t.Parallel()
	cmd, stdout, _ := newSigninTestCmd(t)
	env := func(string) string { return "" }
	runner := &stubAccountListRunner{exitCode: 0}

	err := runOPSignin(context.Background(), cmd, env, runner, "/fake/op", true)
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "no signin needed")
	assert.Equal(t, 1, runner.calls)
}

func TestRunOPSignin_NoTTY_GuidanceOnlyNoRealSignin(t *testing.T) {
	t.Parallel()
	cmd, _, stderr := newSigninTestCmd(t)
	env := func(string) string { return "" }
	runner := &stubAccountListRunner{exitCode: 1}

	err := runOPSignin(context.Background(), cmd, env, runner, "/fake/op", false)
	require.Error(t, err)
	assert.Contains(t, stderr.String(), "OP_SERVICE_ACCOUNT_TOKEN")
	assert.Contains(t, stderr.String(), "eval $(op signin)")
}

func TestRunOPSignin_LLMSession_Blocked(t *testing.T) {
	t.Parallel()
	cmd, _, stderr := newSigninTestCmd(t)
	env := func(k string) string {
		if k == "CLAUDE_CODE" {
			return "1"
		}
		return ""
	}
	runner := &stubAccountListRunner{exitCode: 1}

	err := runOPSignin(context.Background(), cmd, env, runner, "/fake/op", true)
	require.Error(t, err)
	assert.Contains(t, stderr.String(), "interactive-only")
	assert.Contains(t, stderr.String(), "blocked in LLM session")
}
