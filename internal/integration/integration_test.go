//go:build integration

// Package integration_test verifies end-to-end keylatch workflows using an
// in-process memory backend. No external services are required.
package integration_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/agent"
	"github.com/keylatch/keylatch/internal/agentsnippet"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/memory"
	"github.com/keylatch/keylatch/internal/backendtest"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryBackendCompliance runs the shared backend compliance test suite
// against the memory backend to ensure it satisfies the backend.Backend contract.
func TestMemoryBackendCompliance(t *testing.T) {
	backendtest.RunBackendComplianceTests(t, func() backend.Backend {
		return memory.New()
	})
}

// TestStoreConnectAndRetrieve verifies the full connect→get→list→delete
// credential lifecycle using the in-process memory backend.
func TestStoreConnectAndRetrieve(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	const path = "default/ai/openrouter/api_key"

	// Store a credential at the canonical path (S-FIND-23).
	err := store.Set(ctx, path, []byte("sk-or-test-key"), backend.Meta{})
	require.NoError(t, err)

	// Retrieve it.
	val, _, err := store.Get(ctx, path)
	require.NoError(t, err)
	assert.Equal(t, []byte("sk-or-test-key"), val)

	// List connections prefix.
	entries, err := store.List(ctx, "default/ai/")
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, path, entries[0].Path)

	// Delete it.
	require.NoError(t, store.Delete(ctx, path))

	// Confirm gone.
	_, _, err = store.Get(ctx, path)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

// TestConnectionsConnect verifies that connections.Connect stores credentials
// correctly via the memory backend.
func TestConnectionsConnect(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	conn, err := connections.Connect(ctx, "openrouter", connections.ConnectOptions{
		Namespace:      "default",
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte("sk-or-integration-key")},
	}, store)
	require.NoError(t, err)
	assert.Equal(t, "openrouter", conn.Provider)
	assert.Equal(t, "untested", conn.Status)

	// Verify credentials are present in the store.
	entries, err := store.List(ctx, "default/")
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "store must contain entries after Connect")
}

// TestAgentPresetDryRunAllPresets verifies that every registered preset handles
// DryRun=true without writing any files, using the memory backend as the store.
func TestAgentPresetDryRunAllPresets(t *testing.T) {
	// Set HOME to a temp directory so no real config files are modified.
	t.Setenv("HOME", t.TempDir())
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", t.TempDir())
	}

	ctx := context.Background()
	store := memory.New()

	agentNames := []string{
		"claude-code", "codex", "cursor", "openhands",
		"opencode", "openclaw", "nanoclaw", "hermes",
		"n8n", "dify",
	}

	for _, name := range agentNames {
		name := name
		t.Run(name, func(t *testing.T) {
			p, err := agent.Get(name)
			require.NoError(t, err)

			receipt, err := p.Setup(ctx, agent.SetupOptions{
				Mode:   agentsnippet.ProfileModeMCP,
				DryRun: true,
			}, store)
			require.NoError(t, err)
			assert.Empty(t, receipt.FilesWritten, "%s: dry-run must write no files", name)
		})
	}
}
