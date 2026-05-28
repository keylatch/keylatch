package bw_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeBWBin = "/fake/bw"

func testdataBytes(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "testdata")
	b, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err, "testdata file %q must exist", name)
	return b
}

func argKey(name string, args ...string) string {
	parts := append([]string{name}, args...)
	return strings.Join(parts, "|")
}

func makeRunner(key string, resp kexec.MockResponse) *kexec.MockRunner {
	return &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{key: resp},
	}
}

// --- Open tests ---

func TestOpen_MissingBin_ErrUnavailable(t *testing.T) {
	if kexec.Resolve("bw") != "" {
		t.Skip("bw binary found in PATH — skipping unavailable test")
	}
	_, err := bw.Open(bw.Options{Env: func(string) string { return "" }})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable))
	assert.Contains(t, err.Error(), "brew install bitwarden-cli")
}

func TestOpen_HTTPServer_ErrInvalidServer(t *testing.T) {
	_, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Server: "http://vaultwarden.local",
		Env:    func(string) string { return "" },
	})
	require.Error(t, err)
	// S2-4: http:// rejected.
	assert.Contains(t, err.Error(), "https://")
}

func TestOpen_HTTPSServer_OK(t *testing.T) {
	runner := &kexec.MockRunner{}
	b, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Server: "https://vaultwarden.example.com",
		Runner: runner,
		Env:    func(string) string { return "" },
	})
	require.NoError(t, err)
	require.NotNil(t, b)
}

func TestOpen_MissingSession_NoError(t *testing.T) {
	// Missing BW_SESSION at Open does NOT return an error.
	runner := &kexec.MockRunner{}
	b, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Runner: runner,
		Env:    func(string) string { return "" },
	})
	require.NoError(t, err)
	require.NotNil(t, b)
}

// --- Get tests ---

func TestGet_ValidItem_ReturnsValue(t *testing.T) {
	fixture := testdataBytes(t, "item_get_openrouter.json")
	key := argKey(fakeBWBin, "get", "item", "openrouter")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "KEYLATCH_CANARY_PHASE2_0xDEADBEEF", string(val))
	assert.Equal(t, "bw", meta.Backend)
}

func TestGet_MissingField_ErrNotFound(t *testing.T) {
	fixture := testdataBytes(t, "item_get_openrouter.json")
	key := argKey(fakeBWBin, "get", "item", "openrouter")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound))
}

func TestGet_LockedVault_ErrLocked(t *testing.T) {
	lockedStderr := []byte("Vault is locked.")
	statusFixture := testdataBytes(t, "status_locked.json")

	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "get", "item", "openrouter"): {
				Stderr:   lockedStderr,
				ExitCode: 1,
			},
			argKey(fakeBWBin, "status"): {
				Stdout:   statusFixture,
				ExitCode: 0,
			},
		},
	}

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked))
	// Hint present (S2-7: hint, not raw session).
	assert.Contains(t, err.Error(), "BW_SESSION")
}

func TestGet_NoSessionFlag_InArgs(t *testing.T) {
	// S2-7: --session flag must never appear in Runner args.
	fixture := testdataBytes(t, "item_get_openrouter.json")
	key := argKey(fakeBWBin, "get", "item", "openrouter")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Runner: runner,
		Env: func(k string) string {
			if k == "BW_SESSION" {
				return "test-session-token"
			}
			return ""
		},
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)

	// Assert --session is NEVER in the recorded args.
	calls := runner.CallsCopy()
	for _, c := range calls {
		for _, arg := range c.Args {
			assert.False(t, strings.HasPrefix(arg, "--session"),
				"S2-7: --session must not appear in subprocess args, got: %q", arg)
		}
	}
}

// --- List tests ---

func TestList_ZeroFillsValues(t *testing.T) {
	fixture := testdataBytes(t, "item_list_keylatch.json")
	key := argKey(fakeBWBin, "list", "items", "--search=keylatch")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := bw.Open(bw.Options{Bin: fakeBWBin, Runner: runner, Env: func(string) string { return "" }})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	// S2-3: canary must not appear (values are empty in list fixture).
	for _, e := range entries {
		assert.NotContains(t, e.Path, "CANARY")
	}
}

func TestList_AutoSync_False_NoSyncCall(t *testing.T) {
	fixture := testdataBytes(t, "item_list_keylatch.json")
	key := argKey(fakeBWBin, "list", "items", "--search=keylatch")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := bw.Open(bw.Options{
		Bin:      fakeBWBin,
		Runner:   runner,
		AutoSync: false,
		Env:      func(string) string { return "" },
	})
	require.NoError(t, err)

	_, err = b.List(context.Background(), "")
	require.NoError(t, err)

	// No bw sync call should have been made.
	syncCallCount := 0
	for _, c := range runner.CallsCopy() {
		for _, arg := range c.Args {
			if arg == "sync" {
				syncCallCount++
			}
		}
	}
	assert.Equal(t, 0, syncCallCount, "bw sync must not be called when AutoSync=false")
}

func TestList_AutoSync_True_SyncCallFirst(t *testing.T) {
	fixture := testdataBytes(t, "item_list_keylatch.json")
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			argKey(fakeBWBin, "sync"):                               {ExitCode: 0},
			argKey(fakeBWBin, "list", "items", "--search=keylatch"): {Stdout: fixture, ExitCode: 0},
		},
	}

	b, err := bw.Open(bw.Options{
		Bin:      fakeBWBin,
		Runner:   runner,
		AutoSync: true,
		Env:      func(string) string { return "" },
	})
	require.NoError(t, err)

	_, err = b.List(context.Background(), "")
	require.NoError(t, err)

	// bw sync must have been called.
	syncFound := false
	for _, c := range runner.CallsCopy() {
		for _, arg := range c.Args {
			if arg == "sync" {
				syncFound = true
			}
		}
	}
	assert.True(t, syncFound, "bw sync must be called when AutoSync=true")
}

// --- Vaultwarden server URL test ---

func TestOpen_VaultwardenURL_InConfig(t *testing.T) {
	runner := &kexec.MockRunner{}
	b, err := bw.Open(bw.Options{
		Bin:    fakeBWBin,
		Server: "https://vaultwarden.internal",
		Runner: runner,
		Env:    func(string) string { return "" },
	})
	require.NoError(t, err)
	require.NotNil(t, b)
}
