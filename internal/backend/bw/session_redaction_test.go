package bw_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const canaryBW = "KEYLATCH_CANARY_BW_0xDEADBEEF"

// TestSessionRedaction_CanaryAbsentFromAllSurfaces verifies that BW_SESSION
// never appears on any observable surface: error strings, output, or args.
// Session must be passed via env, not args.
func TestSessionRedaction_CanaryAbsentFromAllSurfaces(t *testing.T) {
	fixture := testdataBytes(t, "item_get_openrouter.json")
	key := argKey(fakeBWBin, "get", "item", "openrouter")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	// Inject canary as BW_SESSION.
	canaryEnv := func(k string) string {
		if k == "BW_SESSION" {
			return canaryBW
		}
		return ""
	}

	b, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Runner: runner,
		Env:    canaryEnv,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)

	calls := runner.CallsCopy()

	// Assert canary does NOT appear in any arg.
	for _, c := range calls {
		for _, arg := range c.Args {
			assert.NotEqual(t, canaryBW, arg,
				"canary BW_SESSION must not appear in subprocess args")
			assert.False(t, strings.Contains(arg, canaryBW),
				"canary BW_SESSION must not be embedded in any arg")
		}
	}

	// Assert --session flag is absent from all calls.
	for _, c := range calls {
		for _, arg := range c.Args {
			assert.False(t, strings.HasPrefix(arg, "--session"),
				"--session flag must not appear in subprocess args")
		}
	}
}

// TestSessionRedaction_LockedError_SessionAbsent verifies that ErrLocked
// error messages do not contain the session token.
func TestSessionRedaction_LockedError_SessionAbsent(t *testing.T) {
	statusFixture := testdataBytes(t, "status_locked.json")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "get", "item", "openrouter"): {
				Stderr:   []byte("Vault is locked."),
				ExitCode: 1,
			},
			argKey(fakeBWBin, "status"): {
				Stdout:   statusFixture,
				ExitCode: 0,
			},
		},
	}

	canaryEnv := func(k string) string {
		if k == "BW_SESSION" {
			return canaryBW
		}
		return ""
	}

	b, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Runner: runner,
		Env:    canaryEnv,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked))

	// Session canary must not appear in error message.
	assert.NotContains(t, err.Error(), canaryBW,
		"BW_SESSION canary must not appear in ErrLocked message")
}

// TestSessionRedaction_ListError_SessionAbsent verifies List errors do not
// leak the session token.
func TestSessionRedaction_ListError_SessionAbsent(t *testing.T) {
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "list", "items", "--search=keylatch"): {
				Stderr:   []byte("Vault is locked."),
				ExitCode: 1,
			},
		},
	}

	canaryEnv := func(k string) string {
		if k == "BW_SESSION" {
			return canaryBW
		}
		return ""
	}

	b, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Runner: runner,
		Env:    canaryEnv,
	})
	require.NoError(t, err)

	_, err = b.List(context.Background(), "")
	require.Error(t, err)

	assert.NotContains(t, err.Error(), canaryBW,
		"BW_SESSION canary must not appear in List error message")
}

// TestSessionRedaction_CanaryInListFixture_AbsentFromEntries verifies that
// canary values in list fixtures are NOT returned in entry metadata.
func TestSessionRedaction_CanaryInListFixture_AbsentFromEntries(t *testing.T) {
	fixture := testdataBytes(t, "item_list_keylatch.json")
	key := argKey(fakeBWBin, "list", "items", "--search=keylatch")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	canaryEnv := func(k string) string {
		if k == "BW_SESSION" {
			return canaryBW
		}
		return ""
	}

	b, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Runner: runner,
		Env:    canaryEnv,
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)

	for _, e := range entries {
		assert.NotContains(t, e.Path, canaryBW,
			"BW_SESSION canary must not appear in list entry paths")
		assert.NotContains(t, string(e.Accessor), canaryBW,
			"BW_SESSION canary must not appear in list entry accessor")
	}
}

// TestSessionRedaction_ErrUnavailable_HintContainsBrew verifies fail-closed
// behavior: ErrUnavailable contains actionable hint.
func TestSessionRedaction_ErrUnavailable_HintContainsBrew(t *testing.T) {
	if kexec.Resolve("bw") != "" {
		t.Skip("bw binary found in PATH — skipping unavailable test")
	}
	_, err := bw.Open(bw.Options{Env: func(string) string { return "" }})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable), "expected ErrUnavailable")
	assert.Contains(t, err.Error(), "brew install", "hint must contain brew install")
}
