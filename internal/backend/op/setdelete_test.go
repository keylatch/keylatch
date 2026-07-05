package op_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/op"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openWithRunner(t *testing.T, runner *kexec.MockRunner) backend.Backend {
	t.Helper()
	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)
	return b
}

// TestSet_CreatesWhenMissing: the existence probe gets an empty response
// (item absent), so Set must issue `op item create` with the classified
// category and concealed field type.
func TestSet_CreatesWhenMissing(t *testing.T) {
	createKey := argKey(fakeOpBin, "item", "create",
		"--category=API Credential",
		"--title=openrouter",
		"--vault=Keylatch",
		"--tags=keylatch,ns:default",
		"api_key[concealed]=sk-new",
		"--format=json",
	)
	runner := makeRunner(createKey, kexec.MockResponse{Stdout: []byte(`{"id":"newitem"}`), ExitCode: 0})
	b := openWithRunner(t, runner)

	err := b.Set(context.Background(), "default/openrouter/api_key", []byte("sk-new"), backend.Meta{})
	require.NoError(t, err)
	assert.Equal(t, 1, runner.CountCallsWithArg("--category=API Credential"), "create path must be used")
}

// TestSet_EditsWhenExists: the existence probe returns a valid item, so Set
// must issue `op item edit`.
func TestSet_EditsWhenExists(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	getKey := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	editKey := argKey(fakeOpBin, "item", "edit", "openrouter",
		"--vault=Keylatch",
		"api_key[concealed]=sk-upd",
		"--format=json",
	)
	runner := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		getKey:  {Stdout: fixture, ExitCode: 0},
		editKey: {Stdout: []byte(`{"id":"abc123opitem"}`), ExitCode: 0},
	}}
	b := openWithRunner(t, runner)

	err := b.Set(context.Background(), "default/openrouter/api_key", []byte("sk-upd"), backend.Meta{})
	require.NoError(t, err)
	assert.Equal(t, 1, runner.CountCallsWithArg("edit"), "edit path must be used")
}

func TestSet_AuthFailure_ErrLocked(t *testing.T) {
	createKey := argKey(fakeOpBin, "item", "create",
		"--category=API Credential",
		"--title=openrouter",
		"--vault=Keylatch",
		"--tags=keylatch,ns:default",
		"api_key[concealed]=v",
		"--format=json",
	)
	runner := makeRunner(createKey, kexec.MockResponse{
		Stderr: []byte("[ERROR] you are not currently signed in"), ExitCode: 1,
	})
	b := openWithRunner(t, runner)

	err := b.Set(context.Background(), "default/openrouter/api_key", []byte("v"), backend.Meta{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked), "got: %v", err)
}

func TestSet_InvalidPath(t *testing.T) {
	b := openWithRunner(t, &kexec.MockRunner{})
	err := b.Set(context.Background(), "nopath", []byte("v"), backend.Meta{})
	require.Error(t, err)
}

func TestDelete_Success(t *testing.T) {
	delKey := argKey(fakeOpBin, "item", "delete", "openrouter", "--vault=Keylatch")
	runner := makeRunner(delKey, kexec.MockResponse{ExitCode: 0})
	b := openWithRunner(t, runner)

	require.NoError(t, b.Delete(context.Background(), "default/openrouter/api_key"))
}

func TestDelete_NotFound(t *testing.T) {
	delKey := argKey(fakeOpBin, "item", "delete", "missing", "--vault=Keylatch")
	runner := makeRunner(delKey, kexec.MockResponse{
		Stderr: []byte(`"missing" isn't an item in the "Keylatch" vault`), ExitCode: 1,
	})
	b := openWithRunner(t, runner)

	err := b.Delete(context.Background(), "default/missing/api_key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrNotFound), "got: %v", err)
}

func TestDelete_InvalidPath(t *testing.T) {
	b := openWithRunner(t, &kexec.MockRunner{})
	require.Error(t, b.Delete(context.Background(), "nopath"))
}

func TestIdentityAndClose(t *testing.T) {
	b := openWithRunner(t, &kexec.MockRunner{})
	assert.Equal(t, "op", b.Name())
	assert.NotEmpty(t, b.Capabilities())
	assert.NoError(t, b.Close())
}

// Versioned/meta stubs must consistently return ErrNotSupported.
func TestVersionedStubs_NotSupported(t *testing.T) {
	b := openWithRunner(t, &kexec.MockRunner{})
	ctx := context.Background()

	if _, err := b.GetVersioned(ctx, "p", 1); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("GetVersioned: %v", err)
	}
	if err := b.SetVersioned(ctx, "p", 1, nil); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("SetVersioned: %v", err)
	}
	if err := b.DeleteVersioned(ctx, "p", 1); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("DeleteVersioned: %v", err)
	}
}

// Meta stubs (GetMeta/SetMeta/ListMeta) return ErrNotSupported.
func TestMetaStubs_NotSupported(t *testing.T) {
	b := openWithRunner(t, &kexec.MockRunner{})
	ctx := context.Background()

	if _, err := b.GetMeta(ctx, "p"); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("GetMeta: %v", err)
	}
	if err := b.SetMeta(ctx, "p", meta.Meta{}); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("SetMeta: %v", err)
	}
	if _, err := b.ListMeta(ctx, "p"); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("ListMeta: %v", err)
	}
}

// TestList_ParsesItems covers the happy List path with two tagged items.
func TestList_ParsesItems(t *testing.T) {
	listKey := argKey(fakeOpBin, "item", "list", "--vault=Keylatch", "--tags=keylatch", "--format=json")
	stdout := []byte(`[{"id":"a1","title":"openrouter","tags":["keylatch"],"fields":[{"label":"api_key"}]},{"id":"b2","title":"github","tags":["keylatch"],"fields":[{"label":"token"}]}]`)
	runner := makeRunner(listKey, kexec.MockResponse{Stdout: stdout, ExitCode: 0})
	b := openWithRunner(t, runner)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

// TestList_AuthFailure surfaces ErrLocked.
func TestList_AuthFailure(t *testing.T) {
	listKey := argKey(fakeOpBin, "item", "list", "--vault=Keylatch", "--tags=keylatch", "--format=json")
	runner := makeRunner(listKey, kexec.MockResponse{Stderr: []byte("authentication required"), ExitCode: 1})
	b := openWithRunner(t, runner)

	_, err := b.List(context.Background(), "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrLocked), "got: %v", err)
}

// TestList_BadJSON surfaces a decode error.
func TestList_BadJSON(t *testing.T) {
	listKey := argKey(fakeOpBin, "item", "list", "--vault=Keylatch", "--tags=keylatch", "--format=json")
	runner := makeRunner(listKey, kexec.MockResponse{Stdout: []byte("{not json"), ExitCode: 0})
	b := openWithRunner(t, runner)

	_, err := b.List(context.Background(), "")
	require.Error(t, err)
}
