package mcp

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipWithoutSocketTransport skips tests that serve the socket transport,
// which Windows does not offer.
func skipWithoutSocketTransport(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the socket transport is not available on Windows")
	}
}

// Windows serves stdio only: the socket transport refuses instead of
// accepting connections whose peer cannot be verified.
func TestSocketTransportRefusedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	s, err := New(ServerOptions{Transport: TransportTCP, ConnectionAuth: AuthBearerLegacy})
	require.NoError(t, err)
	assert.ErrorIs(t, s.ServeTCP(context.Background(), newMockStore(), nil), ErrSocketTransportUnsupported)
}
