package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBearerTTLExceedsCapRejected verifies that a TokenTTL > 1h is rejected.
func TestBearerTTLExceedsCapRejected(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")
	t.Setenv("CODEX_ENV", "")
	t.Setenv("CREDENTIALS_LLM_SESSION", "")

	s, err := New(ServerOptions{
		Transport:      TransportTCP,
		ConnectionAuth: AuthBearerLegacy,
		TokenTTL:       "24h", // exceeds 1h cap
	})
	require.NoError(t, err, "New should succeed; TTL is validated in ServeTCP")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := newMockStore()
	err = s.ServeTCP(ctx, store, nil)
	assert.ErrorIs(t, err, ErrTTLExceedsCap,
		"TokenTTL=24h must return ErrTTLExceedsCap")
}

// TestBearerTTLOneHourAccepted verifies that TokenTTL=1h is accepted.
func TestBearerTTLOneHourAccepted(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "")

	s, err := New(ServerOptions{
		Transport:      TransportTCP,
		ConnectionAuth: AuthBearerLegacy,
		TokenTTL:       "1h",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel so ServeTCP returns quickly

	store := newMockStore()
	err = s.ServeTCP(ctx, store, nil)
	// Context was cancelled; should return nil or context error, not TTL error.
	assert.NotErrorIs(t, err, ErrTTLExceedsCap,
		"TokenTTL=1h must not return ErrTTLExceedsCap")
}

// TestStdioModeNoToken verifies that stdio mode does not
// accept a session token.
func TestStdioModeNoToken(t *testing.T) {
	_, err := New(ServerOptions{
		Transport:    TransportStdio,
		SessionToken: "should-not-be-here",
	})
	assert.ErrorIs(t, err, ErrTokenInStdioMode)
}
