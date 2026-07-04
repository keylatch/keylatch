package cli_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireVerifiedSession_HumanSessionUnaffected(t *testing.T) {
	t.Parallel()
	// No signals at all — human session. daemonUp is never even consulted
	// meaningfully here since ClassifySession returns SignalNone.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), func() bool { return false })
	assert.NoError(t, err)
}

func TestRequireVerifiedSession_HeuristicOnly_DaemonDown_FailsClosed(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{"CLAUDE_CODE": "1"})
	err := cli.RequireVerifiedSession(env, func() bool { return false })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYLATCH_ALLOW_UNVERIFIED_SESSION")
}

func TestRequireVerifiedSession_HeuristicOnly_DaemonUp_Allowed(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{"CLAUDE_CODE": "1"})
	err := cli.RequireVerifiedSession(env, func() bool { return true })
	assert.NoError(t, err)
}

func TestRequireVerifiedSession_HeuristicOnly_NilDaemonCheck_FailsClosed(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{"CLAUDE_CODE": "1"})
	err := cli.RequireVerifiedSession(env, nil)
	require.Error(t, err)
}

func TestRequireVerifiedSession_EscapeHatch_RestoresOldBehavior(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{
		"CLAUDE_CODE":                        "1",
		llmcontext.EnvAllowUnverifiedSession: "1",
	})
	err := cli.RequireVerifiedSession(env, func() bool { return false })
	assert.NoError(t, err, "escape hatch must bypass enforcement even with daemon down")
}

func TestRequireVerifiedSession_TicketPresent_NotGatedByDaemon(t *testing.T) {
	t.Parallel()
	// SignalTicket is corroborated by a stronger signal than the heuristic —
	// RequireVerifiedSession must not additionally require daemonUp here;
	// existing IsLLMSession-based guards (GuardLLMSession/GuardRuntime) are
	// the authority for this case.
	env := lookupWith(map[string]string{"KEYLATCH_LLM_TICKET": "some-ticket-value"})
	err := cli.RequireVerifiedSession(env, func() bool { return false })
	assert.NoError(t, err)
}

func TestRequireVerifiedSession_DaemonIPCActive_NotGatedByDaemonUp(t *testing.T) {
	t.Parallel()
	// No KEYLATCH_DAEMON_SOCKET configured in this test harness (llmcontext's
	// IPC client is exercised in its own package tests), so this falls back
	// to SignalNone/SignalHeuristic depending on other env vars — verifying
	// here only that an empty env with no signals is unaffected regardless
	// of the daemonUp callback's value.
	env := lookupWith(map[string]string{})
	err := cli.RequireVerifiedSession(env, func() bool { return false })
	assert.NoError(t, err)
}
