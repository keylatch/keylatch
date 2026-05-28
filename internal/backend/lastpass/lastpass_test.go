package lastpass_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/lastpass"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeLpassBin = "/fake/lpass"

func argKey(name string, args ...string) string {
	parts := append([]string{name}, args...)
	return strings.Join(parts, "|")
}

func openWithRunner(t *testing.T, runner kexec.CommandRunner, username string) *lastpass.LastPassBackend {
	t.Helper()
	b, err := lastpass.Open(lastpass.Options{
		Bin:      fakeLpassBin,
		Username: username,
		Runner:   runner,
	})
	require.NoError(t, err)
	return b
}

func TestLastPassGet_HappyPath(t *testing.T) {
	responseJSON := `[{"id":"123456","name":"keylatch/default/db/password","password":"my-db-password"}]`
	key := argKey(fakeLpassBin, "show", "--json", "--field=Password", "keylatch/default/db/password")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stdout: []byte(responseJSON), ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner, "user@example.com")
	val, meta, err := b.Get(context.Background(), "default/db/password")
	require.NoError(t, err)
	assert.Equal(t, "my-db-password", string(val))
	assert.Equal(t, "lastpass", meta.Backend)
	assert.Equal(t, backend.ID("123456"), meta.Accessor)
}

func TestLastPassGet_NotFound(t *testing.T) {
	key := argKey(fakeLpassBin, "show", "--json", "--field=Password", "keylatch/default/missing")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte("Could not find specified account(s)"), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner, "user@example.com")
	_, _, err := b.Get(context.Background(), "default/missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound), "expected ErrNotFound, got: %v", err)
}

func TestLastPassGet_NotLoggedIn(t *testing.T) {
	// S2-9: inject raw stderr with a sensitive phrase; verify it does NOT appear
	// in the returned error but that ErrLocked IS returned.
	rawStderr := "Please login via `lpass login --trust` to authenticate to server at lastpass.com"
	key := argKey(fakeLpassBin, "show", "--json", "--field=Password", "keylatch/default/secret")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte(rawStderr), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner, "user@example.com")
	_, _, err := b.Get(context.Background(), "default/secret")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked), "expected ErrLocked, got: %v", err)
	// S2-9: raw stderr must not be propagated.
	assert.NotContains(t, err.Error(), rawStderr, "raw stderr must not be propagated (S2-9)")
	// Auth hint must be present.
	assert.Contains(t, err.Error(), "lpass login")
}

func TestLastPassSet_ValuePassedViaStdin(t *testing.T) {
	// C1: the value must be passed via stdin in the expected lpass format.
	key := argKey(fakeLpassBin, "add", "--non-interactive", "--name", "keylatch/default/db/password")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner, "user@example.com")
	err := b.Set(context.Background(), "default/db/password", []byte("testvalue"), backend.Meta{})
	require.NoError(t, err)

	require.Len(t, runner.Calls, 1)
	assert.Equal(t, "Username: keylatch\nPassword: testvalue\n", string(runner.Calls[0].Stdin),
		"value must be passed via stdin in lpass add format")
}

func TestLastPassSet_Locked(t *testing.T) {
	rawStderr := "Please login via `lpass login --trust` to authenticate to server at lastpass.com"
	key := argKey(fakeLpassBin, "add", "--non-interactive", "--name", "keylatch/default/db/password")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte(rawStderr), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner, "user@example.com")
	err := b.Set(context.Background(), "default/db/password", []byte("value"), backend.Meta{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked), "expected ErrLocked, got: %v", err)
	assert.NotContains(t, err.Error(), rawStderr, "raw stderr must not be propagated (S2-9)")
}

func TestLastPassDelete_HappyPath(t *testing.T) {
	key := argKey(fakeLpassBin, "rm", "keylatch/default/db/password")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner, "user@example.com")
	err := b.Delete(context.Background(), "default/db/password")
	require.NoError(t, err)
}

func TestLastPassDelete_NotFound(t *testing.T) {
	key := argKey(fakeLpassBin, "rm", "keylatch/default/missing")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stderr: []byte("could not find specified account"), ExitCode: 1},
		},
	}

	b := openWithRunner(t, runner, "user@example.com")
	err := b.Delete(context.Background(), "default/missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound), "expected ErrNotFound, got: %v", err)
}

func TestLastPassList_JsonParsing(t *testing.T) {
	// W7: verify correct parsing with a realistic lpass ls --json response.
	listJSON := `[
		{"id":"111","name":"keylatch/default/db/password"},
		{"id":"222","name":"keylatch/default/ai/openrouter/api_key"},
		{"id":"333","name":"other-app/secret"}
	]`
	key := argKey(fakeLpassBin, "ls", "--json", "--sync=no")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			key: {Stdout: []byte(listJSON), ExitCode: 0},
		},
	}

	b := openWithRunner(t, runner, "user@example.com")
	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	// Only keylatch/ prefixed items (2 out of 3).
	assert.Len(t, entries, 2)

	// Verify paths are correctly parsed.
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	assert.Contains(t, paths, "default/db/password")
	assert.Contains(t, paths, "default/ai/openrouter/api_key")

	// Verify accessors are populated from JSON IDs.
	for _, e := range entries {
		assert.NotEmpty(t, e.Accessor, "accessor must be set from lpass JSON id field")
	}
}

func TestLastPassWarningMessage(t *testing.T) {
	b, err := lastpass.Open(lastpass.Options{
		Bin:    fakeLpassBin,
		Runner: &kexec.MockRunner{},
	})
	require.NoError(t, err)
	msg := b.WarningMessage()
	assert.Contains(t, msg, "breach history")
}

func TestLastPassID_UsernameHashed(t *testing.T) {
	username := "user@example.com"
	b, err := lastpass.Open(lastpass.Options{
		Bin:      fakeLpassBin,
		Username: username,
		Runner:   &kexec.MockRunner{},
	})
	require.NoError(t, err)

	id := b.ID()
	// ID must start with "lastpass:".
	assert.True(t, strings.HasPrefix(id, "lastpass:"), "ID must start with 'lastpass:'")
	// Raw username must not appear in the ID.
	assert.NotContains(t, id, username, "ID must not contain raw username")
	// The hash part should be 16 hex chars.
	hashPart := strings.TrimPrefix(id, "lastpass:")
	assert.Len(t, hashPart, 16, "hash part must be 16 hex chars")
	// Only hex chars.
	for _, c := range hashPart {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"hash must be lowercase hex, got char %q", c)
	}
}
