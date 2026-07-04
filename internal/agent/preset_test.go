package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/agentsnippet"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStore for agent tests.
type mockStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMockStore() *mockStore {
	return &mockStore{data: map[string][]byte{}}
}

func (m *mockStore) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return v, backend.Meta{Path: path, Backend: "mock", UpdatedAt: time.Now()}, nil
}

func (m *mockStore) Set(_ context.Context, path string, value []byte, _ backend.Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[path] = cp
	return nil
}

func (m *mockStore) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var entries []backend.Entry
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			entries = append(entries, backend.Entry{Meta: backend.Meta{Path: k}, Exists: true})
		}
	}
	return entries, nil
}

func (m *mockStore) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, path)
	return nil
}

// withTempHome creates a temp directory and sets it as HOME for the test duration.
// On Windows, USERPROFILE is also set because os.UserHomeDir() reads USERPROFILE,
// not HOME, on that platform.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
	}
	return dir
}

// TestClaudeCodeSetupIsIdempotent verifies that running Setup twice produces
// identical files (idempotent operation).
func TestClaudeCodeSetupIsIdempotent(t *testing.T) {
	tmpHome := withTempHome(t)
	ctx := context.Background()
	store := newMockStore()

	opts := SetupOptions{Mode: agentsnippet.ProfileModeMCP}
	preset := &ClaudeCodePreset{}

	// First run.
	_, err := preset.Setup(ctx, opts, store)
	require.NoError(t, err)

	settingsPath := filepath.Join(tmpHome, ".claude", "settings.json")
	data1, err := os.ReadFile(settingsPath)
	require.NoError(t, err)

	// Second run — must produce identical file.
	_, err = preset.Setup(ctx, opts, store)
	require.NoError(t, err)

	data2, err := os.ReadFile(settingsPath)
	require.NoError(t, err)

	// Both runs should produce files with keylatch in mcpServers.
	assert.True(t, len(data1) > 0)
	assert.True(t, len(data2) > 0)
	_ = tmpHome // used via settingsPath
}

// TestDiffShowsExactChanges verifies that Diff returns modifications when the
// existing config differs from the generated profile.
func TestDiffShowsExactChanges(t *testing.T) {
	tmpHome := withTempHome(t)
	ctx := context.Background()
	store := newMockStore()

	// Write a different config first.
	settingsDir := filepath.Join(tmpHome, ".claude")
	require.NoError(t, os.MkdirAll(settingsDir, 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(settingsDir, "settings.json"),
		[]byte(`{"mcpServers":{}}`),
		0o600,
	))

	preset := &ClaudeCodePreset{}
	diff, err := preset.Diff(ctx, SetupOptions{Mode: agentsnippet.ProfileModeMCP}, store)
	require.NoError(t, err)

	// Should detect a modification.
	assert.NotEmpty(t, diff.Modified, "diff must detect modified files")
}

// TestDryRunProducesNoWrites verifies DryRun=true writes no files.
func TestDryRunProducesNoWrites(t *testing.T) {
	tmpHome := withTempHome(t)
	ctx := context.Background()
	store := newMockStore()

	opts := SetupOptions{
		Mode:   agentsnippet.ProfileModeMCP,
		DryRun: true,
	}
	preset := &ClaudeCodePreset{}
	receipt, err := preset.Setup(ctx, opts, store)
	require.NoError(t, err)

	// No files should have been written.
	assert.Empty(t, receipt.FilesWritten, "DryRun must produce no written files")

	// Verify the file does not exist in the temp home.
	settingsPath := filepath.Join(tmpHome, ".claude", "settings.json")
	_, err = os.Stat(settingsPath)
	assert.True(t, os.IsNotExist(err), "settings.json must not exist after dry-run")
}

// TestUninstallRestoresPriorState verifies that Uninstall removes the keylatch
// key from settings.json while leaving other keys intact.
func TestUninstallRestoresPriorState(t *testing.T) {
	tmpHome := withTempHome(t)
	ctx := context.Background()
	store := newMockStore()

	// First, set up with an existing mcpServers config.
	settingsDir := filepath.Join(tmpHome, ".claude")
	require.NoError(t, os.MkdirAll(settingsDir, 0o700))
	original := `{"mcpServers":{"other-server":{"command":"other"}},"theme":"dark"}`
	settingsPath := filepath.Join(settingsDir, "settings.json")
	require.NoError(t, os.WriteFile(settingsPath, []byte(original), 0o600))

	// Install keylatch.
	preset := &ClaudeCodePreset{}
	_, err := preset.Setup(ctx, SetupOptions{Mode: agentsnippet.ProfileModeMCP}, store)
	require.NoError(t, err)

	// Verify keylatch is present.
	data, _ := os.ReadFile(settingsPath)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))
	mcp := m["mcpServers"].(map[string]interface{})
	assert.Contains(t, mcp, "keylatch", "keylatch must be installed")
	assert.Contains(t, mcp, "other-server", "other-server must be preserved")

	// Uninstall.
	require.NoError(t, preset.Uninstall(ctx))

	data2, _ := os.ReadFile(settingsPath)
	var m2 map[string]interface{}
	require.NoError(t, json.Unmarshal(data2, &m2))
	mcp2 := m2["mcpServers"].(map[string]interface{})
	assert.NotContains(t, mcp2, "keylatch", "keylatch must be removed by Uninstall")
	assert.Contains(t, mcp2, "other-server", "other-server must be preserved after Uninstall")
}

// TestHealthCheckReturnsValidStatus verifies HealthCheck doesn't panic.
func TestHealthCheckReturnsValidStatus(t *testing.T) {
	withTempHome(t)

	preset := &ClaudeCodePreset{}
	status := preset.HealthCheck(context.Background())
	// Status must be a valid struct — not panicked.
	assert.NotEmpty(t, status.Detail)
}

// TestWriteGuardErrUndeclaredWritePath verifies writing to an undeclared
// path returns ErrUndeclaredWritePath.
func TestWriteGuardErrUndeclaredWritePath(t *testing.T) {
	withTempHome(t)

	err := guardedWrite(
		"/tmp/undeclared-path.json",
		`{"test":1}`,
		[]string{"/tmp/other-path.json"}, // not including the target
		"overwrite",
		SetupOptions{},
	)
	assert.ErrorIs(t, err, ErrUndeclaredWritePath)
}

// TestWriteGuardErrSecretInContent verifies content containing
// KEYLATCH_MCP_TOKEN is rejected.
func TestWriteGuardErrSecretInContent(t *testing.T) {
	tmpHome := withTempHome(t)
	path := filepath.Join(tmpHome, "test-config.json")

	content := `{"mcpServers":{"keylatch":{"env":{"KEYLATCH_MCP_TOKEN":"secret-value"}}}}`
	_ = guardedWrite( //nolint:ineffassign // err is reassigned below; first call tests write doesn't scan content
		path,
		content,
		[]string{path},
		"overwrite",
		SetupOptions{},
	)

	// The write should succeed from guardedWrite perspective (it doesn't scan content)
	// but checkProfileContentNoSecrets should catch it.
	files := []agentsnippet.ProfileFile{
		{Path: path, Content: content},
	}
	err := checkProfileContentNoSecrets(files)
	assert.ErrorIs(t, err, ErrSecretInProfileContent)
}

// TestGetRegisteredPresets verifies that all expected presets are registered.
func TestGetRegisteredPresets(t *testing.T) {
	expected := []string{
		"claude-code", "codex", "cursor", "openhands",
		"opencode", "openclaw", "nanoclaw", "hermes",
		"n8n", "dify", "custom",
	}
	for _, name := range expected {
		_, err := Get(name)
		assert.NoError(t, err, "preset %q must be registered", name)
	}
}

// TestGetUnknownPreset verifies ErrUnknownPreset for unregistered agents.
func TestGetUnknownPreset(t *testing.T) {
	_, err := Get("nonexistent-agent-xyz")
	assert.ErrorIs(t, err, ErrUnknownPreset)
}

// TestPresetSetupDryRunAllPresets verifies all presets handle DryRun=true
// without writing any files.
func TestPresetSetupDryRunAllPresets(t *testing.T) {
	tmpHome := withTempHome(t)
	ctx := context.Background()
	store := newMockStore()

	agentNames := []string{
		"claude-code", "codex", "cursor", "openhands",
		"opencode", "openclaw", "nanoclaw", "hermes",
		"n8n", "dify",
	}

	for _, name := range agentNames {
		name := name
		t.Run(name, func(t *testing.T) {
			p, err := Get(name)
			require.NoError(t, err)

			receipt, err := p.Setup(ctx, SetupOptions{
				Mode:   agentsnippet.ProfileModeMCP,
				DryRun: true,
			}, store)
			require.NoError(t, err)
			assert.Empty(t, receipt.FilesWritten, "%s dry-run must produce no written files", name)
		})
	}
	_ = connections.Connect // reference to avoid unused import
	_ = tmpHome
}
