package doctor_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canaryBWSession = "KEYLATCH_CANARY_BW_SESSION_0xDEADBEEF"

// TestDoctor_BWSession_NotInOutput verifies that BW_SESSION value never appears
// in any doctor check output (S2-7).
func TestDoctor_BWSession_NotInOutput(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return filepath.Join(tmp, ".keylatch")
		case "HOME":
			return tmp
		case "BW_SESSION":
			return canaryBWSession
		case "KEYLATCH_BACKEND":
			return "bw"
		}
		return ""
	}
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env})
	require.NoError(t, err)

	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	b, err := json.Marshal(report)
	require.NoError(t, err)
	reportStr := string(b)

	// S2-7: BW_SESSION value must never appear in doctor output.
	assert.NotContains(t, reportStr, canaryBWSession,
		"BW_SESSION canary must not appear in doctor output")
}

// TestDoctor_OPServiceAccountToken_NotInOutput verifies that OP_SERVICE_ACCOUNT_TOKEN
// value never appears in any doctor check output (S2-7).
func TestDoctor_OPServiceAccountToken_NotInOutput(t *testing.T) {
	const canaryOPToken = "KEYLATCH_CANARY_OP_TOKEN_0xDEADBEEF"

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return filepath.Join(tmp, ".keylatch")
		case "HOME":
			return tmp
		case "OP_SERVICE_ACCOUNT_TOKEN":
			return canaryOPToken
		case "KEYLATCH_BACKEND":
			return "op"
		}
		return ""
	}
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: env})
	require.NoError(t, err)

	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	b, err := json.Marshal(report)
	require.NoError(t, err)
	reportStr := string(b)

	// S2-7: OP_SERVICE_ACCOUNT_TOKEN value must never appear in output.
	assert.NotContains(t, reportStr, canaryOPToken,
		"OP_SERVICE_ACCOUNT_TOKEN canary must not appear in doctor output")
}

// TestDoctor_OPBackend_ErrUnavailable_HintPresent verifies that when op binary
// is missing, the doctor hint directs user to install it (SC2-6).
func TestDoctor_OPBackend_ErrUnavailable_HintPresent(t *testing.T) {
	_, env := bootstrappedHome(t)

	probe := newMockProbe()
	// Do not add 'op' to probe — simulates op binary missing.

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	// Find backend.op check and verify install hint is present.
	for _, s := range report.Checks {
		if s.Name == "backend.op" && !s.OK {
			// Should have a fix hint.
			assert.NotEmpty(t, s.Fix)
		}
	}
}
