package protonpass_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/protonpass"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeProtonBin = "/fake/pass-cli"

func argKey(name string, args ...string) string {
	parts := append([]string{name}, args...)
	return strings.Join(parts, "|")
}

func openWithRunner(t *testing.T, runner kexec.CommandRunner) *protonpass.ProtonPassBackend {
	t.Helper()
	b, err := protonpass.Open(protonpass.Options{
		Bin:    fakeProtonBin,
		Runner: runner,
	})
	require.NoError(t, err)
	return b
}

func TestProtonPassGet_HappyPath(t *testing.T) {
	responseJSON := `{"metadata":{"name":"keylatch/default/ai/openrouter/api_key"},"content":{"note":"sk-test-value-123"}}`
	key := argKey(fakeProtonBin, "item", "get", "keylatch/default/ai/openrouter/api_key", "--output", "json")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stdout: []byte(responseJSON), ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner)
	val, meta, err := b.Get(context.Background(), "default/ai/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "sk-test-value-123", string(val))
	assert.Equal(t, "proton-pass", meta.Backend)
}

func TestProtonPassGet_NotFound(t *testing.T) {
	key := argKey(fakeProtonBin, "item", "get", "keylatch/default/missing", "--output", "json")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte("error: item not found"), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner)
	_, _, err := b.Get(context.Background(), "default/missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound), "expected ErrNotFound, got: %v", err)
}

func TestProtonPassGet_Locked(t *testing.T) {
	// Inject a raw stderr that contains a sensitive URL; verify it does NOT
	// appear in the returned error but that ErrLocked IS returned.
	rawStderr := "not authenticated to server at https://api.proton.me"
	key := argKey(fakeProtonBin, "item", "get", "keylatch/default/secret", "--output", "json")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte(rawStderr), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner)
	_, _, err := b.Get(context.Background(), "default/secret")
	require.Error(t, err)
	// Raw stderr phrase must not appear in the error.
	assert.True(t, errors.Is(err, backend.ErrLocked), "expected ErrLocked, got: %v", err)
	assert.NotContains(t, err.Error(), rawStderr, "raw stderr must not be propagated")
	// Auth hint must be present.
	assert.Contains(t, err.Error(), "pass-cli auth login")
}

func TestProtonPassGet_BinaryNotFound(t *testing.T) {
	// Open with a nonexistent binary path — Resolve won't be called since Bin is not set
	// and pass-cli is not in PATH in test environment.
	if kexec.Resolve("pass-cli") != "" {
		t.Skip("pass-cli found in PATH — skipping unavailable test")
	}
	_, err := protonpass.Open(protonpass.Options{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable), "expected ErrUnavailable, got: %v", err)
}

func TestProtonPassSet_SecretNotInArgs(t *testing.T) {
	// C3: the secret must NOT appear in the args slice — only "-" as stdin sentinel.
	secret := []byte("super-secret-value-xyz")
	key := argKey(fakeProtonBin, "item", "create", "--type", "login", "--name", "keylatch/prod/api_key", "--note", "-")
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
		assert.NotContains(t, arg, string(secret), "secret must not appear in process args")
	}
	// Verify secret IS in stdin.
	assert.Equal(t, secret, call.Stdin, "secret must be passed via stdin")
}

func TestProtonPassSet_HappyPath(t *testing.T) {
	key := argKey(fakeProtonBin, "item", "create", "--type", "login", "--name", "keylatch/default/db/password", "--note", "-")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner)
	err := b.Set(context.Background(), "default/db/password", []byte("new-value"), backend.Meta{})
	require.NoError(t, err)
}

func TestProtonPassSet_Locked(t *testing.T) {
	rawStderr := "not authenticated to server at https://api.proton.me"
	key := argKey(fakeProtonBin, "item", "create", "--type", "login", "--name", "keylatch/default/db/password", "--note", "-")
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

func TestProtonPassDelete_HappyPath(t *testing.T) {
	key := argKey(fakeProtonBin, "item", "delete", "keylatch/default/db/password")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner)
	err := b.Delete(context.Background(), "default/db/password")
	require.NoError(t, err)
}

func TestProtonPassDelete_NotFound(t *testing.T) {
	key := argKey(fakeProtonBin, "item", "delete", "keylatch/default/missing")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte("error: item not found"), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner)
	err := b.Delete(context.Background(), "default/missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound), "expected ErrNotFound, got: %v", err)
}

func TestProtonPassList_ReturnsMetadataOnly(t *testing.T) {
	listJSON := `[
		{"ItemID":"id1","name":"keylatch/default/ai/openrouter/api_key"},
		{"ItemID":"id2","name":"keylatch/default/db/password"},
		{"ItemID":"id3","name":"other-app/secret"}
	]`
	key := argKey(fakeProtonBin, "item", "list", "--output", "json")
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

	// No value bytes in entries.
	for _, e := range entries {
		assert.Empty(t, e.Accessor, "accessor must be empty in list output")
		assert.NotContains(t, e.Path, "CANARY")
		assert.NotContains(t, e.Path, "other-app")
	}
}
