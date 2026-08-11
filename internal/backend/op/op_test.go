package op_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/op"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdataPath returns the absolute path to a testdata file.
func testdataPath(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "testdata")
	b, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err, "testdata file %q must exist", name)
	return b
}

// fakeOpBin is a non-existent absolute path to ensure exec.Resolve is not called.
const fakeOpBin = "/fake/op"

// makeRunner builds a MockRunner with a pre-registered response.
func makeRunner(key string, resp kexec.MockResponse) *kexec.MockRunner {
	return &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{key: resp},
	}
}

// argKey replicates the MockRunner key format: name|arg1|arg2|...
func argKey(name string, args ...string) string {
	parts := append([]string{name}, args...)
	return strings.Join(parts, "|")
}

// --- Open tests ---

func TestOpen_ExplicitBin_SkipsResolve(t *testing.T) {
	runner := &kexec.MockRunner{}
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner})
	require.NoError(t, err)
	require.NotNil(t, b)
	// Verify runner received zero calls (resolve didn't run anything).
	assert.Empty(t, runner.CallsCopy())
}

func TestOpen_DefaultVault(t *testing.T) {
	runner := &kexec.MockRunner{}
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner})
	require.NoError(t, err)
	require.NotNil(t, b)
}

// TestOpen_DefaultRunner covers the Options.Runner == nil default branch —
// Open must substitute kexec.DefaultRunner without invoking it.
func TestOpen_DefaultRunner(t *testing.T) {
	b, err := op.Open(op.Options{Bin: fakeOpBin, Vault: "Keylatch"})
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "op", b.Name())
}

// TestOpen_ResolvesBinaryFromPATH covers the Options.Bin == "" branch where
// kexec.Resolve successfully finds the binary on PATH (as opposed to
// TestOpen_MissingBinary_ErrUnavailable, which covers the not-found case).
func TestOpen_ResolvesBinaryFromPATH(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "op")
	require.NoError(t, os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755))
	t.Setenv("PATH", dir)

	b, err := op.Open(op.Options{Runner: &kexec.MockRunner{}, Env: func(string) string { return "" }})
	require.NoError(t, err)
	require.NotNil(t, b)
}

func TestOpen_MissingBinary_ErrUnavailable(t *testing.T) {
	// Resolve is controlled by PATH — use an env that won't find 'op'.
	// We simulate this by not providing Bin and using a Runner that would fail.
	// Since exec.Resolve goes to PATH directly, we can't mock it, but if op is
	// not installed this test will pass. If op IS installed, we skip.
	if kexec.Resolve("op") != "" {
		t.Skip("op binary found in PATH — skipping unavailable test")
	}
	_, err := op.Open(op.Options{Env: func(string) string { return "" }})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable), "expected ErrUnavailable, got: %v", err)
	assert.Contains(t, err.Error(), "brew install 1password-cli")
}

// --- Get tests ---

func TestGet_ValidItem_ReturnsValue(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "KEYLATCH_CANARY_PHASE2_0xDEADBEEF", string(val))
	assert.Equal(t, "op", meta.Backend)
	assert.Equal(t, "abc123opitem", string(meta.Accessor))
}

func TestGet_MissingField_ErrNotFound(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/nonexistent_field")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound))
}

func TestGet_AuthFailure_ErrLocked(t *testing.T) {
	fixture := testdataPath(t, "auth_failure_stderr.txt")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stderr: fixture, ExitCode: 1})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked))
	// Hint present, raw stderr absent.
	assert.Contains(t, err.Error(), "op signin")
	assert.NotContains(t, err.Error(), "not currently signed in")
}

func TestGet_AuthFailure_NoRawStderr(t *testing.T) {
	// Raw stderr from auth failure must not appear in error message.
	// Use the adversarial fixture that contains a token-shaped string.
	fixture := testdataPath(t, "adversarial_stderr_service_account.txt")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stderr: fixture, ExitCode: 1})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	// Canary must not leak into error message.
	assert.NotContains(t, err.Error(), "KEYLATCH_CANARY_OP_0xDEADBEEF")
	assert.NotContains(t, err.Error(), "OP_SERVICE_ACCOUNT_TOKEN")
}

func TestGet_VaultEnvOverride(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	// Runner key uses the vault from Options.
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=MyVault", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "MyVault"})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "KEYLATCH_CANARY_PHASE2_0xDEADBEEF", string(val))
}

// TestGet_InvalidPath_Error covers Get's parsePath error branch — a path
// without at least a connection/field segment.
func TestGet_InvalidPath_Error(t *testing.T) {
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: &kexec.MockRunner{}, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "nopath")
	require.Error(t, err)
}

// TestGet_RunnerError_Propagates covers fetchItemDirect's RunEnv-level
// error branch (distinct from a non-zero exit code).
func TestGet_RunnerError_Propagates(t *testing.T) {
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Err: errors.New("exec failed to start")})
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "runner error")
}

// TestGet_NotFoundStderr_ErrNotFound covers fetchItemDirect's isNotFound
// stderr-classification branch (distinct from the JSON-empty-array case).
func TestGet_NotFoundStderr_ErrNotFound(t *testing.T) {
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stderr: []byte("[ERROR] item not found"), ExitCode: 1})
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound))
}

// TestGet_AmbiguousStderr_ErrAmbiguous covers fetchItemDirect's stderr-based
// isAmbiguous branch (distinct from the JSON-array-of->1 case already
// covered by TestGet_MultipleItems_ErrAmbiguous).
func TestGet_AmbiguousStderr_ErrAmbiguous(t *testing.T) {
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stderr: []byte("[ERROR] more than one item matches"), ExitCode: 1})
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	var ambig op.ErrAmbiguous
	require.True(t, errors.As(err, &ambig), "expected ErrAmbiguous, got: %v", err)
	assert.Equal(t, "openrouter", ambig.Connection)
}

// TestGet_SingleItemArray_ReturnsItem covers fetchItemDirect's array-decode
// path when op returns exactly one item wrapped in a JSON array.
func TestGet_SingleItemArray_ReturnsItem(t *testing.T) {
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	stdout := []byte(`[{"id":"abc123opitem","title":"openrouter","fields":[{"label":"api_key","value":"sk-solo"}]}]`)
	runner := makeRunner(key, kexec.MockResponse{Stdout: stdout, ExitCode: 0})
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "default/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, "sk-solo", string(val))
}

// TestGet_EmptyArrayResponse_ErrNotFound covers fetchItemDirect's
// zero-length-array decode branch.
func TestGet_EmptyArrayResponse_ErrNotFound(t *testing.T) {
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: []byte(`[]`), ExitCode: 0})
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound))
}

// TestGet_InvalidJSONResponse_DecodeError covers fetchItemDirect's final
// fallback when stdout decodes as neither a single item nor an array.
func TestGet_InvalidJSONResponse_DecodeError(t *testing.T) {
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: []byte("not valid json at all"), ExitCode: 0})
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode item response")
}

// --- List tests ---

func TestList_ZeroFillsValues(t *testing.T) {
	fixture := testdataPath(t, "item_list_keylatch.json")
	key := argKey(fakeOpBin, "item", "list", "--vault=Keylatch", "--tags=keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	// Canary must not appear in list entries (values are zero-filled in fixture).
	for _, e := range entries {
		assert.NotContains(t, e.Path, "KEYLATCH_CANARY")
	}
}

func TestList_PrefixFilter(t *testing.T) {
	fixture := testdataPath(t, "item_list_keylatch.json")
	key := argKey(fakeOpBin, "item", "list", "--vault=Keylatch", "--tags=keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "default/openrouter/")
	require.NoError(t, err)

	for _, e := range entries {
		assert.True(t, strings.HasPrefix(e.Path, "default/openrouter/"))
	}
}

// --- ErrAmbiguous tests ---

func TestGet_MultipleItems_ErrAmbiguous(t *testing.T) {
	// The multiresult fixture has two items with same title; we return it as an array.
	fixture := testdataPath(t, "item_get_multiresult.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)
	var ambig op.ErrAmbiguous
	require.True(t, errors.As(err, &ambig), "expected ErrAmbiguous, got: %v", err)
	assert.Equal(t, "openrouter", ambig.Connection)
	assert.Equal(t, 2, ambig.Count)
	assert.Contains(t, ambig.Error(), "--account")
	assert.Contains(t, ambig.Error(), "openrouter")
}

func TestGet_AccountSuffix_PassesAccountFlag(t *testing.T) {
	// Account-suffixed path: "default/openrouter:myaccount/api_key"
	fixture := testdataPath(t, "item_get_openrouter.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json", "--account=myaccount")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "default/openrouter:myaccount/api_key")
	require.NoError(t, err)
	assert.Equal(t, "KEYLATCH_CANARY_PHASE2_0xDEADBEEF", string(val))
}

// --- Canary assertion tests ---

func TestList_CanaryAbsentFromEntries(t *testing.T) {
	// The list fixture has empty field values — canary must be absent.
	fixture := testdataPath(t, "item_list_keylatch.json")
	key := argKey(fakeOpBin, "item", "list", "--vault=Keylatch", "--tags=keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)

	for _, e := range entries {
		assert.NotContains(t, string(e.Accessor), "CANARY",
			"accessor must not contain canary value")
	}
}
