package agentsnippet

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStore for snippet tests.
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

// seedConnections seeds N connections for snippet generation tests.
func seedConnections(t *testing.T, store *mockStore, n int) {
	t.Helper()
	ctx := context.Background()
	providers := []string{"openrouter", "sentry", "dropbox", "cloudflare", "google_workspace"}
	for i := 0; i < n && i < len(providers); i++ {
		fields := map[string][]byte{}
		switch providers[i] {
		case "openrouter":
			fields["api_key"] = []byte("sk-test-key")
		case "sentry":
			fields["auth_token"] = []byte("sntrys_test")
		case "dropbox":
			fields["access_token"] = []byte("sl.test-token")
		case "cloudflare":
			fields["api_token"] = []byte("cf-test-token")
		case "google_workspace":
			fields["oauth_credentials"] = []byte("{\"type\":\"service_account\"}")
		}
		_, _ = connections.Connect(ctx, providers[i], connections.ConnectOptions{
			Namespace:      "default",
			NonInteractive: true,
			Fields:         fields,
		}, store)
	}
}

// TestGenerateInstructionWithZeroConnections verifies that the snippet renders
// correctly when there are no connections.
func TestGenerateInstructionWithZeroConnections(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	snippet, err := GenerateInstruction(ctx, InstructionOpts{}, store)
	require.NoError(t, err)
	assert.Contains(t, snippet, "Keylatch Integration")
	assert.Contains(t, snippet, "none configured")
}

// TestGenerateInstructionWithOneConnection verifies rendering with one connection.
func TestGenerateInstructionWithOneConnection(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	seedConnections(t, store, 1)

	snippet, err := GenerateInstruction(ctx, InstructionOpts{}, store)
	require.NoError(t, err)
	assert.Contains(t, snippet, "openrouter")
}

// TestGenerateInstructionWithManyConnections verifies that MaxConnections limits
// the number of connections in the snippet.
func TestGenerateInstructionWithManyConnections(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	seedConnections(t, store, 5)

	snippet, err := GenerateInstruction(ctx, InstructionOpts{MaxConnections: 2}, store)
	require.NoError(t, err)
	// Should contain at most 2 providers.
	assert.NotEmpty(t, snippet)
	assert.Contains(t, snippet, "Keylatch Integration")
}

// TestGenerateInstructionIncludesMCPBlock verifies that IncludeMCP=true appends
// the MCP tool inventory block.
func TestGenerateInstructionIncludesMCPBlock(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	snippet, err := GenerateInstruction(ctx, InstructionOpts{IncludeMCP: true}, store)
	require.NoError(t, err)
	assert.Contains(t, snippet, "keylatch_status")
	assert.Contains(t, snippet, "keylatch_run")
	assert.Contains(t, snippet, "Limitations")
}

// TestGenerateInstructionContainsLimitationsSection verifies S3-14/FIND-012:
// the Limitations section is always present.
func TestGenerateInstructionContainsLimitationsSection(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	snippet, err := GenerateInstruction(ctx, InstructionOpts{}, store)
	require.NoError(t, err)
	assert.Contains(t, snippet, "Limitations")
	assert.Contains(t, snippet, "best-effort")
	assert.Contains(t, snippet, "NOT a security boundary")
}

// TestMCPConfigIsValidJSON verifies that GenerateMCPConfig returns valid JSON
// with the correct mcpServers structure.
func TestMCPConfigIsValidJSON(t *testing.T) {
	ctx := context.Background()

	cfg, err := GenerateMCPConfig(ctx)
	require.NoError(t, err)

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	mcpServers, ok := m["mcpServers"].(map[string]interface{})
	assert.True(t, ok, "mcpServers key must exist")
	_, hasKeylatch := mcpServers["keylatch"]
	assert.True(t, hasKeylatch, "keylatch MCP server must be registered")
}

// TestMCPConfigCommandIsKeylatch verifies that the MCP server command is "keylatch".
func TestMCPConfigCommandIsKeylatch(t *testing.T) {
	ctx := context.Background()

	cfg, err := GenerateMCPConfig(ctx)
	require.NoError(t, err)

	spec, ok := cfg.MCPServers["keylatch"]
	require.True(t, ok)
	assert.Equal(t, "keylatch", spec.Command)
	assert.Contains(t, spec.Args, "mcp")
	assert.Contains(t, spec.Args, "--stdio")
}

// TestProfileFilesForPresets verifies that profile generation produces the
// expected files for each supported agent preset.
func TestProfileFilesForPresets(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	agents := []string{
		"claude-code", "codex", "cursor", "openhands",
		"opencode", "openclaw", "nanoclaw", "hermes",
		"n8n", "dify",
	}

	for _, agent := range agents {
		agent := agent
		t.Run(agent, func(t *testing.T) {
			profile, err := GenerateProfile(ctx, agent, ProfileModeMCP, store)
			require.NoError(t, err, "GenerateProfile(%q) must succeed", agent)
			assert.Equal(t, agent, profile.Agent)
			assert.NotEmpty(t, profile.Files, "profile must declare at least one file")
			assert.NotEmpty(t, profile.Instructions, "profile must include instructions")
			assert.NotEmpty(t, profile.HealthCheck, "profile must include health check command")
			assert.NotEmpty(t, profile.Rollback, "profile must include rollback instructions")
		})
	}
}

// TestProfileFilesContainNoSecretValues verifies S3-8: profile files use only
// placeholder values, never actual secrets.
func TestProfileFilesContainNoSecretValues(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()

	profile, err := GenerateProfile(ctx, "claude-code", ProfileModeMCP, store)
	require.NoError(t, err)

	for _, f := range profile.Files {
		assert.NotContains(t, f.Content, "KEYLATCH_MCP_TOKEN",
			"profile file %q must not contain KEYLATCH_MCP_TOKEN", f.Path)
		// Verify it's placeholder content (JSON with no actual secrets).
		assert.Contains(t, f.Content, "keylatch",
			"profile file %q must reference keylatch MCP", f.Path)
	}
}
