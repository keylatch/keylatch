package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/localonly"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"github.com/keylatch/keylatch/internal/runapproval"
	"github.com/keylatch/keylatch/internal/testutil"
)

const runPlan = "run for a agent caller, tier D5, connection stripe\n  command:  \"make\" \"test\"\n"

func pendingRun(t *testing.T, dir string) string {
	t.Helper()
	ar, err := approval.RequestNewPlan(context.Background(), dir, "daemon:agent", "run:D5", "stripe", "hash-of-the-plan", runPlan, 5*time.Minute)
	require.NoError(t, err)
	return ar.Token
}

func TestApproveShowsTheExactPlanAndAsksForPresence(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)
	withApprover(t)
	seen := presencetest.Record(t)
	token := pendingRun(t, approvalsDir)

	cmd := newApproveCmd()
	var stderr bytes.Buffer
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{token})
	require.NoError(t, cmd.ExecuteContext(context.Background()))

	assert.Contains(t, stderr.String(), `"make" "test"`, "the prompt shows the command")
	require.Len(t, *seen, 1)
	assert.Contains(t, (*seen)[0], "run.approve")
	assert.Contains(t, (*seen)[0], `"make" "test"`)
	assert.Contains(t, (*seen)[0], "request hash: hash-of-the-plan", "the presence summary is bound to the request hash")

	ar, err := approval.Get(context.Background(), approvalsDir, token)
	require.NoError(t, err)
	assert.Equal(t, approval.StatusApproved, ar.Status)
}

func TestApprovingARunNeedsAHumanPresent(t *testing.T) {
	approvalsDir, _ := setupApprovalDir(t)
	t.Setenv("KEYLATCH_APPROVALS_DIR", approvalsDir)
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)
	withApprover(t)
	presencetest.NoTerminal(t)
	token := pendingRun(t, approvalsDir)

	cmd := newApproveCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token})
	err := cmd.ExecuteContext(context.Background())
	requireExitCode(t, err, exitcode.SecurityBlock)

	ar, err := approval.Get(context.Background(), approvalsDir, token)
	require.NoError(t, err)
	assert.Equal(t, approval.StatusPending, ar.Status, "a refused approval decides nothing")

	presencetest.Decline(t)
	cmd = newApproveCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{token})
	requireExitCode(t, cmd.ExecuteContext(context.Background()), exitcode.SecurityBlock)
}

func TestBindingApprovalCoversTheExactChange(t *testing.T) {
	seen := presencetest.Record(t)
	approve := bindingApproval(context.Background(), "billing")
	require.NoError(t, approve(connections.BindingChange{Kind: connections.ChangeWidened, HostsBefore: []string{"a.example"}, HostsAfter: []string{"a.example", "b.example"}}))
	require.Len(t, *seen, 1)
	for _, want := range []string{"binding.change", "widened the binding of billing", "hosts before: a.example", "hosts after:  a.example, b.example", "added:   b.example"} {
		assert.Contains(t, (*seen)[0], want)
	}

	// A proof for one host set is not a proof for another.
	proof, err := presence.Require(context.Background(), presence.ActionBindingChange, runapproval.BindingSummary("billing", connections.ChangeWidened, []string{"a.example"}, []string{"a.example", "b.example"}))
	require.NoError(t, err)
	other := runapproval.BindingSummary("billing", connections.ChangeWidened, []string{"a.example"}, []string{"a.example", "evil.example"})
	assert.False(t, proof.Covers(presence.ActionBindingChange, other))
}

func TestBindingChangeWithoutPresenceIsRefusedEvenForAHuman(t *testing.T) {
	presencetest.NoTerminal(t)
	approve := bindingApproval(context.Background(), "billing")
	err := approve(connections.BindingChange{Kind: connections.ChangeCreated, HostsAfter: []string{"api.billing.example"}})
	requireExitCode(t, err, exitcode.SecurityBlock)

	presencetest.Decline(t)
	err = approve(connections.BindingChange{Kind: connections.ChangeCreated, HostsAfter: []string{"api.billing.example"}})
	requireExitCode(t, err, exitcode.SecurityBlock)
}

func TestConnectCustomWritesNothingUntilAHumanApprovesTheChange(t *testing.T) {
	ctx, st, em := context.Background(), newMapStore(), &recordingEmitter{}
	in := customInputFor("a.example.com:443", "b.example.com:443")
	in.Approve = bindingApproval(ctx, "billing-internal")

	presencetest.NoTerminal(t)
	err := connectCustom(ctx, &bytes.Buffer{}, st, "billing-internal", in, connections.CallerHuman, em)
	requireExitCode(t, err, exitcode.SecurityBlock)
	assert.Empty(t, st.data, "a creation without presence writes nothing, even for a human")
	require.Len(t, em.events, 1)
	assert.Equal(t, "binding.refused", string(em.events[0].Action))
	assert.Equal(t, connections.ChangeCreated, em.events[0].Extra["attempted"])

	seen := presencetest.Record(t)
	require.NoError(t, connectCustom(ctx, &bytes.Buffer{}, st, "billing-internal", in, connections.CallerHuman, em))
	require.Len(t, *seen, 1)
	assert.Contains(t, (*seen)[0], "hosts after:  a.example.com:443, b.example.com:443")
	assert.NotEmpty(t, st.data)

	// Widening needs a fresh approval that names the new set; narrowing needs none.
	*seen = nil
	wider := customInputFor("a.example.com:443", "b.example.com:443", "c.example.com:443")
	wider.Fields = nil
	wider.Approve = in.Approve
	require.NoError(t, connectCustom(ctx, &bytes.Buffer{}, st, "billing-internal", wider, connections.CallerHuman, em))
	require.Len(t, *seen, 1)
	assert.Contains(t, (*seen)[0], "added:   c.example.com:443")

	*seen = nil
	narrower := customInputFor("a.example.com:443")
	narrower.Fields = nil
	narrower.Approve = in.Approve
	require.NoError(t, connectCustom(ctx, &bytes.Buffer{}, st, "billing-internal", narrower, connections.CallerHuman, em))
	assert.Empty(t, *seen, "narrowing a binding asks nobody")

	presencetest.Decline(t)
	wider.Approve = in.Approve
	err = connectCustom(ctx, &bytes.Buffer{}, st, "billing-internal", wider, connections.CallerHuman, em)
	requireExitCode(t, err, exitcode.SecurityBlock)
}

func TestWeakeningALocalOnlyModeNeedsPresence(t *testing.T) {
	seen := presencetest.Record(t)
	summaryWanted := []string{"local_only.weaken", "weaken the local-only delivery of app.JWT_SECRET", "mode before: ephemeral", "mode after:  none"}
	weaken := func(old, next localonly.Mode) error {
		summary := "weaken the local-only delivery of app.JWT_SECRET\n  mode before: " + orNoneMode(old) + "\n  mode after:  " + orNoneMode(next)
		_, err := requirePresence(context.Background(), presence.ActionLocalOnlyWeaken, "%s", summary)
		return err
	}
	require.NoError(t, weaken(localonly.Ephemeral, ""))
	for _, want := range summaryWanted {
		assert.Contains(t, (*seen)[0], want)
	}
	assert.Equal(t, "none", orNoneMode(""))
	assert.Equal(t, "operation", orNoneMode(localonly.Operation))
	assert.True(t, strings.Contains(runPlan, "make"))
}
