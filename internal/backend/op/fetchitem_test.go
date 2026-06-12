package op_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/op"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGet_AccountDisambiguation: a "connection:account" path must pass
// --account to op.
func TestGet_AccountDisambiguation(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter",
		"--vault=Keylatch", "--format=json", "--account=workslug")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "default/openrouter:workslug/api_key")
	require.NoError(t, err)
	assert.NotEmpty(t, val)
	assert.Equal(t, 1, runner.CountCallsWithArg("--account=workslug"))
}

// TestGet_CacheHit: a second Get for the same connection within the TTL must
// not invoke the runner again.
func TestGet_CacheHit(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := makeRunner(key, kexec.MockResponse{Stdout: fixture, ExitCode: 0})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)
	ctx := context.Background()

	_, _, err = b.Get(ctx, "default/openrouter/api_key")
	require.NoError(t, err)
	_, _, err = b.Get(ctx, "default/openrouter/api_key")
	require.NoError(t, err)

	assert.Len(t, runner.CallsCopy(), 1, "second Get must be served from cache")
}

// TestGet_SingleFlight: concurrent Gets for the same connection collapse to
// one subprocess invocation.
func TestGet_SingleFlight(t *testing.T) {
	fixture := testdataPath(t, "item_get_openrouter.json")
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := &kexec.MockRunner{
		Responses:        map[string]kexec.MockResponse{key: {Stdout: fixture, ExitCode: 0}},
		SimulatedLatency: 50 * time.Millisecond,
	}

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, gerr := b.Get(ctx, "default/openrouter/api_key")
			assert.NoError(t, gerr)
		}()
	}
	wg.Wait()

	assert.Len(t, runner.CallsCopy(), 1, "concurrent Gets must single-flight")
}

// TestGet_ContextCancelled: a cancelled context aborts the fetch wait.
func TestGet_ContextCancelled(t *testing.T) {
	key := argKey(fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json")
	runner := &kexec.MockRunner{
		Responses:        map[string]kexec.MockResponse{key: {ExitCode: 0}},
		SimulatedLatency: 2 * time.Second,
	}

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, _, err = b.Get(ctx, "default/openrouter/api_key")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
