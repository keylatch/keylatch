package cli_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Non-raw-exposure paths (rawCredentialExposure=false) are always a no-op ---

func TestRequireVerifiedSession_GatewayMode_UnaffectedRegardlessOfSession(t *testing.T) {
	t.Parallel()
	// SignalNone (human-looking) with no escape hatch — would fail closed on
	// a raw-exposure path, but rawCredentialExposure=false (gateway/proxy
	// `run`) must always be a no-op: the child never receives a raw secret
	// in this mode.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), false, false)
	assert.NoError(t, err)

	// Even an LLM-heuristic session (spoofed or not) is unaffected in gateway mode.
	err = cli.RequireVerifiedSession(lookupWith(map[string]string{"CLAUDE_CODE": "1"}), false, false)
	assert.NoError(t, err)
}

// --- Raw-exposure paths (rawCredentialExposure=true): the M2 gate itself ---

func TestRequireVerifiedSession_HumanNonLLMSession_GatewayUnaffected(t *testing.T) {
	t.Parallel()
	// A genuinely human, non-LLM session using gateway mode is never gated —
	// covered above. Included here to make the "human + gateway" combination
	// explicit per the fix's required test matrix.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), false, false)
	assert.NoError(t, err)
}

func TestRequireVerifiedSession_SignalNone_DirectRun_BlockedWithoutCorroboration(t *testing.T) {
	t.Parallel()
	// This is the spoof-to-human hole M2 closes: no LLM signal at all
	// (SignalNone) on a raw-exposure path (direct/brokered run, or get), with
	// no ticket, no daemon-tracked session, and no escape hatch — must fail
	// closed.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYLATCH_ALLOW_UNVERIFIED_SESSION")
}

func TestRequireVerifiedSession_HeuristicOnly_DirectRun_FailsClosed(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{"CLAUDE_CODE": "1"})
	err := cli.RequireVerifiedSession(env, true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYLATCH_ALLOW_UNVERIFIED_SESSION")
}

func TestRequireVerifiedSession_ReachableUnauthenticatedDaemon_IsNotABypass(t *testing.T) {
	t.Parallel()
	// Regression test for the fixed M2 hole: a bare, unauthenticated
	// reachability check against keylatchd's HTTP health endpoint
	// (daemon.IsRunning) used to be accepted as corroboration on its own.
	// That check is session/PID-unbound — ANY local process could satisfy
	// it merely by starting a listener on the daemon's port (e.g. `keylatch
	// ui --port 7890 --no-open &`), defeating M2's fail-closed intent. There
	// is no longer a daemonUp parameter at all: RequireVerifiedSession no
	// longer has any way to accept "a listener is reachable" as
	// corroboration. With no ticket, no SignalDaemonActive (i.e. no
	// authenticated IPC confirmation via KEYLATCH_DAEMON_SOCKET), and no
	// escape hatch, this must still fail closed regardless of whether some
	// process elsewhere has bound the daemon's health port.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYLATCH_ALLOW_UNVERIFIED_SESSION")
}

func TestRequireVerifiedSession_EscapeHatch_Env_RestoresAccess(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{
		llmcontext.EnvAllowUnverifiedSession: "1",
	})
	err := cli.RequireVerifiedSession(env, true, false)
	assert.NoError(t, err, "env escape hatch must bypass enforcement even with no other signals")
}

func TestRequireVerifiedSession_EscapeHatch_Config_RestoresAccess(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{})
	// configAllowsUnverified=true simulates allow_unverified_session: true in config.json.
	err := cli.RequireVerifiedSession(env, true, true)
	assert.NoError(t, err, "config escape hatch must bypass enforcement even with no other signals")
}

func TestRequireVerifiedSession_TicketPresent_RawExposure_Allowed(t *testing.T) {
	t.Parallel()
	// A signed ticket is corroboration on its own.
	env := lookupWith(map[string]string{"KEYLATCH_LLM_TICKET": "some-ticket-value"})
	err := cli.RequireVerifiedSession(env, true, false)
	assert.NoError(t, err)
}

func TestRequireVerifiedSession_TicketPresent_NotGatedByDaemon(t *testing.T) {
	t.Parallel()
	// SignalTicket is corroborated by a stronger signal than the heuristic —
	// RequireVerifiedSession must not additionally require any daemon signal
	// here.
	env := lookupWith(map[string]string{"KEYLATCH_LLM_TICKET": "some-ticket-value"})
	err := cli.RequireVerifiedSession(env, true, false)
	assert.NoError(t, err)
}
