package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"github.com/keylatch/keylatch/internal/testutil"
)

func decide(t *testing.T, verb string, args ...string) error {
	t.Helper()
	cmd := newApproveCmd()
	if verb == "deny" {
		cmd = newDenyCmd()
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	return cmd.ExecuteContext(context.Background())
}

func setupDecision(t *testing.T) (dir, token string) {
	t.Helper()
	dir, _ = setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", dir)
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)
	withApprover(t)
	return dir, createPendingApproval(t, dir)
}

func statusOf(t *testing.T, dir, token string) string {
	t.Helper()
	ar, err := approval.Get(context.Background(), dir, token)
	require.NoError(t, err)
	return ar.Status
}

func TestApproveNeedsPresence(t *testing.T) {
	dir, token := setupDecision(t)

	presencetest.NoTerminal(t)
	requireExitCode(t, decide(t, "approve", token), exitcode.SecurityBlock)
	presencetest.Decline(t)
	requireExitCode(t, decide(t, "approve", token), exitcode.SecurityBlock)
	assert.Equal(t, approval.StatusPending, statusOf(t, dir, token), "a refused approval decides nothing")

	seen := presencetest.Record(t)
	require.NoError(t, decide(t, "approve", token))
	require.Len(t, *seen, 1)
	assert.Contains(t, (*seen)[0], string(presence.ActionApprove))
	assert.Contains(t, (*seen)[0], "request hash: hash123", "the prompt is bound to the request")

	ar, err := approval.Get(context.Background(), dir, token)
	require.NoError(t, err)
	assert.Equal(t, approval.StatusApproved, ar.Status)
	assert.Equal(t, presence.Digest(presence.ActionApprove, approvalSummary(ar)), ar.PresenceDigest, "the record carries the proof it was decided under")
	assert.Equal(t, "tty", ar.PresenceMethod)
}

func TestDenyNeedsPresence(t *testing.T) {
	dir, token := setupDecision(t)

	presencetest.NoTerminal(t)
	requireExitCode(t, decide(t, "deny", token), exitcode.SecurityBlock)
	presencetest.Decline(t)
	requireExitCode(t, decide(t, "deny", token), exitcode.SecurityBlock)
	assert.Equal(t, approval.StatusPending, statusOf(t, dir, token))

	seen := presencetest.Record(t)
	require.NoError(t, decide(t, "deny", token))
	require.Len(t, *seen, 1)
	assert.Contains(t, (*seen)[0], string(presence.ActionDeny))
	assert.Equal(t, approval.StatusDenied, statusOf(t, dir, token))
	ar, err := approval.Get(context.Background(), dir, token)
	require.NoError(t, err)
	assert.NotEmpty(t, ar.PresenceDigest)
}

func TestDenyAllNeedsPresence(t *testing.T) {
	dir, token := setupDecision(t)
	other := createPendingApproval(t, dir)

	presencetest.NoTerminal(t)
	requireExitCode(t, decide(t, "deny", "--all", "--yes"), exitcode.SecurityBlock)
	assert.Equal(t, approval.StatusPending, statusOf(t, dir, token))

	seen := presencetest.Record(t)
	require.NoError(t, decide(t, "deny", "--all", "--yes"))
	require.Len(t, *seen, 1, "one prompt covers the whole batch")
	assert.Contains(t, (*seen)[0], token)
	assert.Contains(t, (*seen)[0], other)
	assert.Equal(t, approval.StatusDenied, statusOf(t, dir, token))
	assert.Equal(t, approval.StatusDenied, statusOf(t, dir, other))
}
