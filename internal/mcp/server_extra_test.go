package mcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonUnixConn is a net.Conn that is intentionally not *net.UnixConn,
// used to test the validatePeerUID type-assertion fast path.
type nonUnixConn struct{ net.Conn }

// ---------------------------------------------------------------------------
// defaultAuthMode
// ---------------------------------------------------------------------------

// TestDefaultAuthModeStdio verifies AuthStdioPipe for stdio transport.
func TestDefaultAuthModeStdio(t *testing.T) {
	mode := defaultAuthMode(TransportStdio)
	assert.Equal(t, AuthStdioPipe, mode)
}

// TestDefaultAuthModeTCP verifies a known auth mode is returned for TCP.
func TestDefaultAuthModeTCP(t *testing.T) {
	mode := defaultAuthMode(TransportTCP)
	validModes := []ConnectionAuthMode{
		AuthUnixPeerCred,
		AuthNamedPipeACL,
		AuthBearerLegacy,
	}
	assert.Contains(t, validModes, mode)
}

// ---------------------------------------------------------------------------
// New: various valid and invalid configs
// ---------------------------------------------------------------------------

func TestNewServerIPv6AllBindRejected(t *testing.T) {
	_, err := New(ServerOptions{
		Transport: TransportTCP,
		Bind:      "::",
	})
	assert.ErrorIs(t, err, ErrForbiddenBind)
}

func TestNewServerIPv6AllBindWithPortRejected(t *testing.T) {
	_, err := New(ServerOptions{
		Transport: TransportTCP,
		Bind:      "[::]:8080",
	})
	assert.ErrorIs(t, err, ErrForbiddenBind)
}

func TestNewServerZeroBindWithPortRejected(t *testing.T) {
	_, err := New(ServerOptions{
		Transport: TransportTCP,
		Bind:      "0.0.0.0:9999",
	})
	assert.ErrorIs(t, err, ErrForbiddenBind)
}

func TestNewServerExplicitConnectionAuth(t *testing.T) {
	s, err := New(ServerOptions{
		Transport:      TransportTCP,
		ConnectionAuth: AuthBearerLegacy,
	})
	require.NoError(t, err)
	assert.Equal(t, AuthBearerLegacy, s.opts.ConnectionAuth)
}

func TestNewServerStdioNoToken(t *testing.T) {
	s, err := New(ServerOptions{Transport: TransportStdio})
	require.NoError(t, err)
	assert.Equal(t, AuthStdioPipe, s.opts.ConnectionAuth)
}

// ---------------------------------------------------------------------------
// Serve: unknown transport returns error
// ---------------------------------------------------------------------------

func TestServeUnknownTransport(t *testing.T) {
	s := &Server{opts: ServerOptions{Transport: Transport("bogus")}}
	store := newMockStore()
	err := s.Serve(context.Background(), store, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

// ---------------------------------------------------------------------------
// ServeTCP: wrong transport returns error
// ---------------------------------------------------------------------------

func TestServeTCPWrongTransport(t *testing.T) {
	s := &Server{opts: ServerOptions{Transport: TransportStdio}}
	store := newMockStore()
	err := s.ServeTCP(context.Background(), store, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stdio")
}

// ---------------------------------------------------------------------------
// ServeTCP: invalid TokenTTL string rejected
// ---------------------------------------------------------------------------

func TestServeTCPInvalidTokenTTL(t *testing.T) {
	s, err := New(ServerOptions{
		Transport:      TransportTCP,
		ConnectionAuth: AuthBearerLegacy,
		TokenTTL:       "not-a-duration",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	store := newMockStore()
	err = s.ServeTCP(ctx, store, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TokenTTL")
}

// ---------------------------------------------------------------------------
// serveBearerLegacy: invalid TTL rejected
// ---------------------------------------------------------------------------

func TestServeBearerLegacyInvalidTokenTTL(t *testing.T) {
	s := &Server{opts: ServerOptions{
		Transport:      TransportTCP,
		ConnectionAuth: AuthBearerLegacy,
		TokenTTL:       "not-a-duration",
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.serveBearerLegacy(ctx, nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ServeTCP: cancellation path (BearerLegacy with valid config)
// ---------------------------------------------------------------------------

func TestServeTCPCancelledImmediately(t *testing.T) {
	s, err := New(ServerOptions{
		Transport:      TransportTCP,
		ConnectionAuth: AuthBearerLegacy,
		Bind:           "127.0.0.1:0",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before any accept

	store := newMockStore()
	err = s.ServeTCP(ctx, store, nil)
	// Should return nil (context cancelled) or at most a listen error.
	// Not an unexpected error.
	if err != nil {
		assert.Contains(t, err.Error(), "listen", "unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// generateNonce
// ---------------------------------------------------------------------------

func TestGenerateNonce(t *testing.T) {
	n1, err := generateNonce()
	require.NoError(t, err)
	assert.Len(t, n1, 64, "nonce must be 64 hex chars (32 bytes)")

	n2, err := generateNonce()
	require.NoError(t, err)
	assert.NotEqual(t, n1, n2)
}

// ---------------------------------------------------------------------------
// nonceRegistry.register
// ---------------------------------------------------------------------------

func TestNonceRegistryRegisterNewNonce(t *testing.T) {
	r := &nonceRegistry{nonces: make(map[string]uint64)}
	err := r.register("abc123", 1)
	assert.NoError(t, err)
}

func TestNonceRegistryRegisterSameNonceSameFD(t *testing.T) {
	r := &nonceRegistry{nonces: make(map[string]uint64)}
	require.NoError(t, r.register("abc123", 1))
	err := r.register("abc123", 1) // idempotent
	assert.NoError(t, err)
}

func TestNonceRegistryRegisterNonceDifferentFD(t *testing.T) {
	r := &nonceRegistry{nonces: make(map[string]uint64)}
	require.NoError(t, r.register("abc123", 1))
	err := r.register("abc123", 2) // conflict
	assert.ErrorIs(t, err, ErrNonceConnectionMismatch)
}

// ---------------------------------------------------------------------------
// newBearerSession: zero TTL defaults to maxBearerTokenTTL
// ---------------------------------------------------------------------------

func TestNewBearerSessionZeroTTLDefaultsToMax(t *testing.T) {
	before := time.Now()
	s := newBearerSession("tok", 0)
	after := time.Now()
	_ = after
	assert.True(t, s.expiresAt.After(before.Add(maxBearerTokenTTL-time.Second)),
		"expiresAt should be ~1h from now when ttl=0")
	assert.True(t, s.expiresAt.Before(before.Add(maxBearerTokenTTL+2*time.Second)),
		"expiresAt should be ~1h from now when ttl=0")
}

// ---------------------------------------------------------------------------
// validatePeerUID: non-unix conn returns false
// ---------------------------------------------------------------------------

func TestValidatePeerUIDNonUnixConn(t *testing.T) {
	conn := &nonUnixConn{}
	result := validatePeerUID(conn, 0)
	assert.False(t, result)
}

// ---------------------------------------------------------------------------
// rateLimiter: window expiry allows another call
// ---------------------------------------------------------------------------

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl := &rateLimiter{
		calls:  make(map[string]time.Time),
		window: 10 * time.Millisecond,
	}
	key := "test-key"

	assert.True(t, rl.Allow(key), "first call allowed")
	assert.False(t, rl.Allow(key), "immediate second call denied")

	time.Sleep(20 * time.Millisecond)
	assert.True(t, rl.Allow(key), "call after window expiry allowed")
}

// ---------------------------------------------------------------------------
// Tool handlers: status and list_connections error paths
// ---------------------------------------------------------------------------

// errStore is a store that always returns an error from List,
// causing connections.Status to fail gracefully.
type errStore struct{}

func (e *errStore) Get(_ interface{}, _ string) ([]byte, interface{}, error) {
	return nil, nil, nil
}

// ---------------------------------------------------------------------------
// Tool handler: describe with empty provider string (covered via invokeHandler)
// ---------------------------------------------------------------------------

func TestDescribeHandlerEmptyProvider(t *testing.T) {
	store := newMockStore()
	handler := makeDescribeHandler(store)
	response := invokeHandler(t, handler, map[string]any{"provider": ""})
	assert.Contains(t, response, "provider")
}

func TestDescribeHandlerUnknownProvider(t *testing.T) {
	store := newMockStore()
	handler := makeDescribeHandler(store)
	response := invokeHandler(t, handler, map[string]any{"provider": "nonexistent-xyz"})
	// Should return an error result but not panic.
	assert.NotEmpty(t, response)
}

// ---------------------------------------------------------------------------
// Tool handler: test handler missing provider
// ---------------------------------------------------------------------------

func TestTestHandlerMissingProvider(t *testing.T) {
	store := newMockStore()
	handler := makeTestHandler(store)
	response := invokeHandler(t, handler, map[string]any{})
	assert.Contains(t, response, "provider")
}

// ---------------------------------------------------------------------------
// Tool handler: status handler error path (store with no data = empty result)
// ---------------------------------------------------------------------------

func TestStatusHandlerEmptyStore(t *testing.T) {
	store := newMockStore()
	handler := makeStatusHandler(store)
	response := invokeHandler(t, handler, nil)
	// No connections → JSON array (may be "[]" or "null" depending on nil slice marshalling)
	assert.True(t, response == "[]" || response == "null", "expected empty JSON array or null, got %q", response)
}

// ---------------------------------------------------------------------------
// Tool handler: list_connections handler empty store
// ---------------------------------------------------------------------------

func TestListConnectionsHandlerEmptyStore(t *testing.T) {
	store := newMockStore()
	handler := makeListConnectionsHandler(store)
	response := invokeHandler(t, handler, nil)
	// Empty store → empty JSON array
	assert.Equal(t, "[]", response)
}

func TestListConnectionsHandlerWithConnection(t *testing.T) {
	store := newMockStore()
	setupCanaryConnection(t, store)
	handler := makeListConnectionsHandler(store)
	response := invokeHandler(t, handler, nil)
	assert.Contains(t, response, "openrouter")
}
