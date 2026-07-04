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
	// SignalNone (human-looking) with daemon down and no escape hatch — would
	// fail closed on a raw-exposure path, but rawCredentialExposure=false
	// (gateway/proxy `run`) must always be a no-op: the child never receives
	// a raw secret in this mode.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), func() bool { return false }, false, false)
	assert.NoError(t, err)

	// Even an LLM-heuristic session (spoofed or not) is unaffected in gateway mode.
	err = cli.RequireVerifiedSession(lookupWith(map[string]string{"CLAUDE_CODE": "1"}), func() bool { return false }, false, false)
	assert.NoError(t, err)
}

// --- Raw-exposure paths (rawCredentialExposure=true): the M2 gate itself ---

func TestRequireVerifiedSession_HumanNonLLMSession_GatewayUnaffected(t *testing.T) {
	t.Parallel()
	// A genuinely human, non-LLM session using gateway mode is never gated —
	// covered above. Included here to make the "human + gateway" combination
	// explicit per the fix's required test matrix.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), func() bool { return false }, false, false)
	assert.NoError(t, err)
}

func TestRequireVerifiedSession_SignalNone_DirectRun_BlockedWithoutCorroboration(t *testing.T) {
	t.Parallel()
	// This is the spoof-to-human hole M2 closes: no LLM signal at all
	// (SignalNone) on a raw-exposure path (direct/brokered run, or get), with
	// no ticket, no daemon, and no escape hatch — must fail closed.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), func() bool { return false }, true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYLATCH_ALLOW_UNVERIFIED_SESSION")
}

func TestRequireVerifiedSession_HeuristicOnly_DirectRun_DaemonDown_FailsClosed(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{"CLAUDE_CODE": "1"})
	err := cli.RequireVerifiedSession(env, func() bool { return false }, true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYLATCH_ALLOW_UNVERIFIED_SESSION")
}

func TestRequireVerifiedSession_RawExposure_DaemonUp_Allowed(t *testing.T) {
	t.Parallel()
	// No env signals at all (SignalNone) — a reachable keylatchd is
	// sufficient corroboration on its own.
	err := cli.RequireVerifiedSession(lookupWith(map[string]string{}), func() bool { return true }, true, false)
	assert.NoError(t, err)
}

func TestRequireVerifiedSession_RawExposure_NilDaemonCheck_FailsClosed(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{})
	err := cli.RequireVerifiedSession(env, nil, true, false)
	require.Error(t, err)
}

func TestRequireVerifiedSession_EscapeHatch_Env_RestoresAccess(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{
		llmcontext.EnvAllowUnverifiedSession: "1",
	})
	err := cli.RequireVerifiedSession(env, func() bool { return false }, true, false)
	assert.NoError(t, err, "env escape hatch must bypass enforcement even with daemon down and no signals")
}

func TestRequireVerifiedSession_EscapeHatch_Config_RestoresAccess(t *testing.T) {
	t.Parallel()
	env := lookupWith(map[string]string{})
	// configAllowsUnverified=true simulates allow_unverified_session: true in config.json.
	err := cli.RequireVerifiedSession(env, func() bool { return false }, true, true)
	assert.NoError(t, err, "config escape hatch must bypass enforcement even with daemon down and no signals")
}

func TestRequireVerifiedSession_TicketPresent_RawExposure_Allowed(t *testing.T) {
	t.Parallel()
	// A signed ticket is corroboration on its own — no daemon needed.
	env := lookupWith(map[string]string{"KEYLATCH_LLM_TICKET": "some-ticket-value"})
	err := cli.RequireVerifiedSession(env, func() bool { return false }, true, false)
	assert.NoError(t, err)
}

func TestRequireVerifiedSession_TicketPresent_NotGatedByDaemon(t *testing.T) {
	t.Parallel()
	// SignalTicket is corroborated by a stronger signal than the heuristic —
	// RequireVerifiedSession must not additionally require daemonUp here.
	env := lookupWith(map[string]string{"KEYLATCH_LLM_TICKET": "some-ticket-value"})
	err := cli.RequireVerifiedSession(env, func() bool { return false }, true, false)
	assert.NoError(t, err)
}
