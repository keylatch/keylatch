package bw_test

import (
	"context"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const envCanaryBW = "KEYLATCH_ENV_SEAM_CANARY_0xC0FFEE"

// TestRunWithSession_InjectsBWSessionViaEnv verifies the M3 seam: BW_SESSION
// reaches the subprocess through CommandRunner.RunEnv's extraEnv, not via
// ambient os.Environ() inheritance and not via argv.
func TestRunWithSession_InjectsBWSessionViaEnv(t *testing.T) {
	fixture := testdataBytes(t, "item_get_openrouter.json")
	key := argKey(fakeBWBin, "get", "item", "openrouter")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	envFn := func(k string) string {
		if k == "BW_SESSION" {
			return envCanaryBW
		}
		return ""
	}

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: envFn})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)

	calls := runner.CallsCopy()
	require.Len(t, calls, 1)

	// The session MUST appear in the recorded extraEnv...
	found := false
	for _, e := range calls[0].Env {
		if e == "BW_SESSION="+envCanaryBW {
			found = true
		}
		// ...as a "KEY=VALUE" pair, not embedded in some other var.
		if strings.Contains(e, envCanaryBW) {
			assert.Equal(t, "BW_SESSION="+envCanaryBW, e,
				"canary must only appear as a clean BW_SESSION=<value> entry")
		}
	}
	assert.True(t, found, "BW_SESSION=<canary> must be present in RunEnv's extraEnv")

	// ...and MUST NOT appear anywhere in argv.
	for _, arg := range calls[0].Args {
		assert.NotContains(t, arg, envCanaryBW, "canary must never appear in argv")
	}
}

// TestRunWithSession_NoSession_EmptyExtraEnv verifies that when no session is
// available (ambient env empty, no cache), RunEnv is called with a nil/empty
// extraEnv rather than an env entry with an empty value.
func TestRunWithSession_NoSession_EmptyExtraEnv(t *testing.T) {
	fixture := testdataBytes(t, "item_get_openrouter.json")
	key := argKey(fakeBWBin, "get", "item", "openrouter")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)

	calls := runner.CallsCopy()
	require.Len(t, calls, 1)
	assert.Empty(t, calls[0].Env, "no BW_SESSION env entry expected when session is unavailable")
}
