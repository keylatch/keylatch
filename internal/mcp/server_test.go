package mcp

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStore implements connections.Store for MCP tests.
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
	return v, backend.Meta{Path: path, Backend: "mock"}, nil
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

// TestNewServerRejectsZeroBind verifies that binding to 0.0.0.0 is rejected.
func TestNewServerRejectsZeroBind(t *testing.T) {
	_, err := New(ServerOptions{
		Transport: TransportTCP,
		Bind:      "0.0.0.0",
	})
	assert.ErrorIs(t, err, ErrForbiddenBind)
}

// TestNewServerRejectsTokenInStdioMode verifies that no bearer token is allowed in stdio mode.
func TestNewServerRejectsTokenInStdioMode(t *testing.T) {
	_, err := New(ServerOptions{
		Transport:    TransportStdio,
		SessionToken: "some-token",
	})
	assert.ErrorIs(t, err, ErrTokenInStdioMode)
}

// TestNewServerDefaultsToStdioPipeAuth verifies that stdio transport defaults to AuthStdioPipe.
func TestNewServerDefaultsToStdioPipeAuth(t *testing.T) {
	s, err := New(ServerOptions{Transport: TransportStdio})
	require.NoError(t, err)
	assert.Equal(t, AuthStdioPipe, s.opts.ConnectionAuth)
}

// TestNewServerTCPBindDefault verifies TCP bind defaults to 127.0.0.1.
func TestNewServerTCPBindDefault(t *testing.T) {
	s, err := New(ServerOptions{Transport: TransportTCP})
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", s.opts.Bind)
}

// TestExactlyFiveToolsRegistered verifies that exactly five tools are registered.
func TestExactlyFiveToolsRegistered(t *testing.T) {
	assert.Equal(t, 5, len(registeredTools), "exactly five tools must be registered")
	assert.Contains(t, registeredTools, "keylatch_status")
	assert.Contains(t, registeredTools, "keylatch_list_connections")
	assert.Contains(t, registeredTools, "keylatch_describe")
	assert.Contains(t, registeredTools, "keylatch_test")
	assert.Contains(t, registeredTools, "keylatch_run")
}

// TestRateLimiterAllowsOncePerWindow verifies the test call rate limiter.
func TestRateLimiterAllowsOncePerWindow(t *testing.T) {
	rl := &rateLimiter{
		calls:  make(map[string]time.Time),
		window: 30 * time.Second,
	}
	key := "test-connection"

	// First call should be allowed.
	assert.True(t, rl.Allow(key), "first call should be allowed")

	// Immediate second call should be denied.
	assert.False(t, rl.Allow(key), "second call within window should be denied")
}

// TestCommandMatchesAllowlist verifies allowlist pre-flight logic.
func TestCommandMatchesAllowlist(t *testing.T) {
	tests := []struct {
		name     string
		cmdLine  string
		prefixes []string
		want     bool
	}{
		{"empty allowlist denies all", "node script.js", []string{}, false},
		{"nil allowlist denies all", "node script.js", nil, false},
		{"matching prefix allowed", "node script.js", []string{"node "}, true},
		{"tsx allowed", "tsx scripts/summarise.ts", []string{"node ", "tsx "}, true},
		{"python3 rejected with node-only list", "python3 -c 'import os'", []string{"node "}, false},
		{"shell injection rejected", "bash -c env", []string{"node ", "tsx "}, false},
		{"env -0 rejected", "env -0", []string{"node ", "tsx "}, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := commandMatchesAllowlist(tc.cmdLine, tc.prefixes)
			assert.Equal(t, tc.want, got, "commandMatchesAllowlist(%q, %v)", tc.cmdLine, tc.prefixes)
		})
	}
}
