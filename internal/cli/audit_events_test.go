package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"github.com/keylatch/keylatch/internal/testutil"
)

// capturedAudit routes the CLI's audit log to a scratch file and returns a
// reader of what was written to it.
func capturedAudit(t *testing.T) (events func() []audit.Event, open func() *audit.Logger) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	require.NoError(t, os.Mkdir(dir, 0o700))
	path := filepath.Join(dir, "audit.log")
	seed, dek := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(seed)
	_, _ = rand.Read(dek)
	open = func() *audit.Logger {
		l, err := audit.Open(path, seed, dek)
		require.NoError(t, err)
		return l
	}
	prev := openAuditLoggerFn
	openAuditLoggerFn = func() (*audit.Logger, func(), error) {
		l := open()
		return l, func() { _ = l.Close() }, nil
	}
	t.Cleanup(func() { openAuditLoggerFn = prev })
	events = func() []audit.Event {
		l := open()
		defer l.Close()
		evs, err := l.Scan(audit.SinceOpts{})
		require.NoError(t, err)
		return evs
	}
	return events, open
}

func actions(evs []audit.Event) []audit.Action {
	out := make([]audit.Action, len(evs))
	for i, e := range evs {
		out[i] = e.Action
	}
	return out
}

func TestPresenceOutcomesAreAudited(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	testutil.ClearLLMSessionEnv(t)
	events, _ := capturedAudit(t)

	presencetest.Approve(t)
	_, err := requirePresence(context.Background(), presence.ActionConfigSet, "Change %s", "x")
	require.NoError(t, err)
	presencetest.Decline(t)
	_, err = requirePresence(context.Background(), presence.ActionConfigSet, "Change %s", "x")
	require.Error(t, err)
	presencetest.NoTerminal(t)
	_, err = requirePresence(context.Background(), presence.ActionConfigSet, "Change %s", "x")
	require.Error(t, err)

	evs := events()
	require.Len(t, evs, 3)
	var results []any
	for _, e := range evs {
		assert.Equal(t, audit.ActionPresenceDecision, e.Action)
		assert.Equal(t, string(presence.ActionConfigSet), e.Extra["operation"])
		results = append(results, e.Extra["result"])
	}
	assert.Equal(t, []any{"approved", "denied", "no_terminal"}, results)
	assert.NotEmpty(t, evs[0].Extra["digest"])
	assert.Equal(t, audit.OutcomeDenied, evs[1].Outcome)
}

func TestPolicyChangeIsAudited(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	testutil.ClearLLMSessionEnv(t)
	events, _ := capturedAudit(t)

	run := func() error {
		cmd := newPolicyDenyCmd()
		cmd.SetArgs([]string{"github", "--as", "agent"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.ExecuteContext(context.Background())
	}

	presencetest.Decline(t)
	require.Error(t, run())
	presencetest.Approve(t)
	require.NoError(t, run())

	evs := events()
	assert.Equal(t, []audit.Action{
		audit.ActionPresenceDecision, audit.ActionPolicyChange,
		audit.ActionPresenceDecision, audit.ActionPolicyChange,
	}, actions(evs))
	assert.Equal(t, audit.OutcomeDenied, evs[1].Outcome)
	assert.Equal(t, audit.OutcomeOK, evs[3].Outcome)
	assert.Equal(t, "github", evs[3].Extra["connection"])
	assert.Equal(t, "deny", evs[3].Extra["change"])
	assert.NotEmpty(t, evs[3].Extra["digest"])
}

func TestConnectSetAndGuardBlockAreAudited(t *testing.T) {
	testutil.SetupHermeticConfig(t)
	events, open := capturedAudit(t)
	ctx := context.Background()

	recordConnect(ctx, "openrouter", "file", nil)
	recordConnect(ctx, "openrouter", "file", errors.New("boom"))
	l := open()
	recordSet(ctx, l, "default/ai/openrouter/api_key", "file", nil)
	recordSet(ctx, l, "openrouter.api_key", "file", errors.New("boom"))
	_ = l.Close()
	recordGuardBlock(ctx, "run", "runtime_mode:direct_classic", "not permitted")

	evs := events()
	assert.Equal(t, []audit.Action{
		audit.ActionConnect, audit.ActionConnect, audit.ActionSet, audit.ActionSet, audit.ActionGuardBlock,
	}, actions(evs))
	assert.Equal(t, audit.OutcomeError, evs[1].Outcome)
	assert.Equal(t, "openrouter", evs[2].Extra["connection"])
	assert.Equal(t, "api_key", evs[2].Extra["field"])
	assert.Equal(t, "openrouter", evs[3].Extra["connection"])
	assert.Equal(t, audit.OutcomeDenied, evs[4].Outcome)
	assert.Equal(t, "runtime_mode:direct_classic", evs[4].Extra["rule"])
}
