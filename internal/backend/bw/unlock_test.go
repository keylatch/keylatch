package bw_test

// unlock_test.go — H5: BitwardenBackend.Unlock (mocked-runner, stdin
// password passthrough, never argv) and the Open() session-cache pickup /
// lockedGuidance() cache-invalidation seam.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const unlockCanaryPassword = "KEYLATCH_CANARY_MASTER_PW_0xFEEDFACE"

func TestUnlock_Success_PasswordViaStdinNeverArgv(t *testing.T) {
	t.Parallel()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "unlock", "--raw"): {
				Stdout:   []byte("s.session-token-abc123\n"),
				ExitCode: 0,
			},
		},
	}

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	token, err := b.Unlock(context.Background(), []byte(unlockCanaryPassword))
	require.NoError(t, err)
	assert.Equal(t, "s.session-token-abc123", token)

	calls := runner.CallsCopy()
	require.Len(t, calls, 1)
	assert.Equal(t, []byte(unlockCanaryPassword), calls[0].Stdin, "password must be piped via stdin")
	for _, arg := range calls[0].Args {
		assert.NotContains(t, arg, unlockCanaryPassword, "password must never appear in argv")
		assert.NotEqual(t, "--session", arg)
	}
}

func TestUnlock_InvalidPassword_ErrLocked(t *testing.T) {
	t.Parallel()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "unlock", "--raw"): {
				Stderr:   []byte("Invalid master password."),
				ExitCode: 1,
			},
		},
	}

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	token, err := b.Unlock(context.Background(), []byte("wrong-password"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked))
	assert.Empty(t, token)
	assert.NotContains(t, err.Error(), "wrong-password")
}

func TestUnlock_EmptyTokenReturned_Errors(t *testing.T) {
	t.Parallel()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "unlock", "--raw"): {
				Stdout:   []byte("\n"),
				ExitCode: 0,
			},
		},
	}

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	token, err := b.Unlock(context.Background(), []byte("some-password"))
	require.Error(t, err)
	assert.Empty(t, token)
}

func TestUnlock_GenericFailure_NoRawStderrLeaked(t *testing.T) {
	t.Parallel()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "unlock", "--raw"): {
				Stderr:   []byte("some unexpected bw internal error text"),
				ExitCode: 3,
			},
		},
	}

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	_, err = b.Unlock(context.Background(), []byte("pw"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "some unexpected bw internal error text")
}

// --- Open() cache pickup + priority ---

func TestOpen_NoAmbientSession_InjectsFromCache(t *testing.T) {
	t.Parallel()
	sessionDir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_BW_SESSION_DIR" {
			return sessionDir
		}
		return "" // no ambient BW_SESSION
	}
	require.NoError(t, bw.SaveSession(env, "cached-token-999", time.Hour))

	fixture := testdataBytes(t, "item_get_openrouter.json")
	key := argKey(fakeBWBin, "get", "item", "openrouter")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: env})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)

	calls := runner.CallsCopy()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].Env, "BW_SESSION=cached-token-999")
}

func TestOpen_AmbientSessionTakesPriorityOverCache(t *testing.T) {
	t.Parallel()
	sessionDir := t.TempDir()
	env := func(k string) string {
		switch k {
		case "KEYLATCH_BW_SESSION_DIR":
			return sessionDir
		case "BW_SESSION":
			return "ambient-token-111"
		}
		return ""
	}
	require.NoError(t, bw.SaveSession(env, "cached-token-should-be-ignored", time.Hour))

	fixture := testdataBytes(t, "item_get_openrouter.json")
	key := argKey(fakeBWBin, "get", "item", "openrouter")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: env})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)

	calls := runner.CallsCopy()
	require.Len(t, calls, 1)
	assert.Contains(t, calls[0].Env, "BW_SESSION=ambient-token-111")
	for _, e := range calls[0].Env {
		assert.NotContains(t, e, "cached-token-should-be-ignored")
	}
}

// --- lockedGuidance() cache invalidation ---

func TestLockedFailure_CacheSourcedSession_InvalidatesCache(t *testing.T) {
	t.Parallel()
	sessionDir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_BW_SESSION_DIR" {
			return sessionDir
		}
		return "" // no ambient BW_SESSION -> session comes from cache
	}
	require.NoError(t, bw.SaveSession(env, "now-invalid-cached-token", time.Hour))

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "get", "item", "openrouter"): {
				Stderr:   []byte("Session key is invalid."),
				ExitCode: 1,
			},
		},
	}

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: env})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked))
	assert.Contains(t, err.Error(), "keylatch bw unlock")

	status, statErr := bw.StatSession(env)
	require.NoError(t, statErr)
	assert.False(t, status.Present, "cache-sourced session must be invalidated after a locked failure")
}

func TestLockedFailure_AmbientSession_DoesNotInvalidateUnrelatedCache(t *testing.T) {
	t.Parallel()
	sessionDir := t.TempDir()
	env := func(k string) string {
		switch k {
		case "KEYLATCH_BW_SESSION_DIR":
			return sessionDir
		case "BW_SESSION":
			return "ambient-token-that-fails"
		}
		return ""
	}
	// A cache entry exists from a previous `bw unlock`, unrelated to this
	// ambient BW_SESSION.
	require.NoError(t, bw.SaveSession(env, "unrelated-cached-token", time.Hour))

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "get", "item", "openrouter"): {
				Stderr:   []byte("Vault is locked."),
				ExitCode: 1,
			},
		},
	}

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: env})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked))

	status, statErr := bw.StatSession(env)
	require.NoError(t, statErr)
	assert.True(t, status.Present, "unrelated cache entry must survive an ambient-BW_SESSION failure")
}
