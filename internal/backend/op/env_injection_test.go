package op_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/op"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const envCanaryOP = "KEYLATCH_ENV_SEAM_CANARY_OP_0xC0FFEE"

// TestFetchItem_InjectsServiceAccountTokenViaEnv verifies the M3 seam: when
// Options.Env reports OP_SERVICE_ACCOUNT_TOKEN, it is forwarded through
// CommandRunner.RunEnv's extraEnv rather than relying solely on ambient
// os.Environ() inheritance, and it never appears in argv.
func TestFetchItem_InjectsServiceAccountTokenViaEnv(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	envFn := func(k string) string {
		if k == "OP_SERVICE_ACCOUNT_TOKEN" {
			return envCanaryOP
		}
		return ""
	}

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Env: envFn})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)

	calls := runner.CallsCopy()
	require.Len(t, calls, 1)

	found := false
	for _, e := range calls[0].Env {
		if e == "OP_SERVICE_ACCOUNT_TOKEN="+envCanaryOP {
			found = true
		}
	}
	assert.True(t, found, "OP_SERVICE_ACCOUNT_TOKEN=<canary> must be present in RunEnv's extraEnv")

	for _, arg := range calls[0].Args {
		assert.NotContains(t, arg, envCanaryOP, "canary must never appear in argv")
	}
}

// TestFetchItem_NoServiceAccountToken_EmptyExtraEnv verifies that when
// Options.Env reports no OP_SERVICE_ACCOUNT_TOKEN, RunEnv is called with an
// empty extraEnv rather than injecting an empty-valued entry.
func TestFetchItem_NoServiceAccountToken_EmptyExtraEnv(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)

	calls := runner.CallsCopy()
	require.Len(t, calls, 1)
	assert.Empty(t, calls[0].Env, "no OP_SERVICE_ACCOUNT_TOKEN env entry expected when unset")
}
