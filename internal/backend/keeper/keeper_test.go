package keeper_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/keeper"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeKeeperBin = "/fake/keeper"

func argKey(name string, args ...string) string {
	parts := append([]string{name}, args...)
	return strings.Join(parts, "|")
}

func openWithRunner(t *testing.T, runner kexec.CommandRunner) *keeper.KeeperBackend {
	t.Helper()
	b, err := keeper.Open(keeper.Options{
		Bin:    fakeKeeperBin,
		Runner: runner,
	})
	require.NoError(t, err)
	return b
}

func TestKeeperGet_HappyPath(t *testing.T) {
	responseJSON := `{"record_uid":"uid-abc","title":"keylatch/default/db/password","password":"super-secret-value"}`
	key := argKey(fakeKeeperBin, "get", "--format=json", "keylatch/default/db/password")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stdout: []byte(responseJSON), ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner)
	val, meta, err := b.Get(context.Background(), "default/db/password")
	require.NoError(t, err)
	assert.Equal(t, "super-secret-value", string(val))
	assert.Equal(t, "keeper", meta.Backend)
	assert.Equal(t, backend.ID("uid-abc"), meta.Accessor)
}

func TestKeeperGet_NotFound(t *testing.T) {
	key := argKey(fakeKeeperBin, "get", "--format=json", "keylatch/default/missing")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte("error: record not found"), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner)
	_, _, err := b.Get(context.Background(), "default/missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound), "expected ErrNotFound, got: %v", err)
}

func TestKeeperGet_NotLoggedIn(t *testing.T) {
	// Inject raw stderr with a sensitive phrase; verify it does NOT appear in
	// the returned error but that ErrLocked IS returned.
	rawStderr := "error: not authenticated to vault server at https://keepersecurity.com"
	key := argKey(fakeKeeperBin, "get", "--format=json", "keylatch/default/secret")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte(rawStderr), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner)
	_, _, err := b.Get(context.Background(), "default/secret")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked), "expected ErrLocked, got: %v", err)
	// Raw stderr must not be propagated.
	assert.NotContains(t, err.Error(), rawStderr, "raw stderr must not be propagated")
	// Auth hint must be present.
	assert.Contains(t, err.Error(), "keeper login")
}

func TestKeeperSet_SecretNotInArgs(t *testing.T) {
	// C2: the secret must NOT appear in the args slice — only "-" as stdin sentinel.
	secret := []byte("super-secret-keeper-value")
	key := argKey(fakeKeeperBin, "add", "--title", "keylatch/prod/api_key", "--pass", "-", "--folder", "keylatch")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner)
	err := b.Set(context.Background(), "prod/api_key", secret, backend.Meta{})
	require.NoError(t, err)

	require.Len(t, runner.Calls, 1)
	call := runner.Calls[0]
	// Verify secret is NOT in args.
	for _, arg := range call.Args {
		assert.NotEqual(t, string(secret), arg, "secret must not appear in process args")
		assert.NotContains(t, arg, string(secret), "secret must not appear in process args")
	}
	// Verify "-" is the pass value, not the secret.
	assert.Contains(t, call.Args, "-", "pass value must be stdin sentinel")
	// Verify secret IS in stdin.
	assert.Equal(t, secret, call.Stdin, "secret must be passed via stdin")
}

func TestKeeperSet_HappyPath(t *testing.T) {
	key := argKey(fakeKeeperBin, "add", "--title", "keylatch/default/db/password", "--pass", "-", "--folder", "keylatch")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner)
	err := b.Set(context.Background(), "default/db/password", []byte("new-value"), backend.Meta{})
	require.NoError(t, err)
}

func TestKeeperSet_Locked(t *testing.T) {
	rawStderr := "error: not authenticated to vault server at https://keepersecurity.com"
	key := argKey(fakeKeeperBin, "add", "--title", "keylatch/default/db/password", "--pass", "-", "--folder", "keylatch")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte(rawStderr), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner)
	err := b.Set(context.Background(), "default/db/password", []byte("value"), backend.Meta{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked), "expected ErrLocked, got: %v", err)
	assert.NotContains(t, err.Error(), rawStderr, "raw stderr must not be propagated")
}

func TestKeeperDelete_HappyPath(t *testing.T) {
	key := argKey(fakeKeeperBin, "delete", "keylatch/default/db/password")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner)
	err := b.Delete(context.Background(), "default/db/password")
	require.NoError(t, err)
}

func TestKeeperDelete_NotFound(t *testing.T) {
	key := argKey(fakeKeeperBin, "delete", "keylatch/default/missing")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte("error: record not found"), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner)
	err := b.Delete(context.Background(), "default/missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound), "expected ErrNotFound, got: %v", err)
}

func TestKeeperBinaryFallback(t *testing.T) {
	// Both keeper and ksm are absent; Open should return ErrUnavailable.
	if kexec.Resolve("keeper") != "" || kexec.Resolve("ksm") != "" {
		t.Skip("keeper or ksm found in PATH — skipping unavailable test")
	}
	_, err := keeper.Open(keeper.Options{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable), "expected ErrUnavailable, got: %v", err)
}

func TestKeeperList_MetadataOnly(t *testing.T) {
	listJSON := `[
		{"record_uid":"uid1","title":"keylatch/default/ai/openrouter/api_key"},
		{"record_uid":"uid2","title":"keylatch/default/db/password"},
		{"record_uid":"uid3","title":"other-app/secret"}
	]`
	key := argKey(fakeKeeperBin, "ls", "--format=json")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stdout: []byte(listJSON), ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner)
	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	// Should only include keylatch/ prefixed items (2 out of 3).
	assert.Len(t, entries, 2)

	// No secret values in entries — only metadata.
	for _, e := range entries {
		assert.NotContains(t, e.Path, "other-app")
		assert.NotEmpty(t, e.Accessor, "accessor (record_uid) should be set")
	}
}
