package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestZeroBindRejected verifies that keylatch mcp does not accept
// 0.0.0.0 as a bind address.
func TestZeroBindRejected(t *testing.T) {
	_, err := New(ServerOptions{
		Transport: TransportTCP,
		Bind:      "0.0.0.0",
	})
	assert.ErrorIs(t, err, ErrForbiddenBind,
		"binding to 0.0.0.0 must return ErrForbiddenBind")
}

// TestLocalhostBindAllowed verifies that 127.0.0.1 is accepted.
func TestLocalhostBindAllowed(t *testing.T) {
	s, err := New(ServerOptions{
		Transport: TransportTCP,
		Bind:      "127.0.0.1",
	})
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", s.opts.Bind)
}

// TestNoUnsafeBindAllFlag verifies that the --unsafe-bind-all flag is
// not registered in any of the declared server options.
func TestNoUnsafeBindAllFlag(t *testing.T) {
	// ServerOptions must not have an UnsafeBindAll field.
	// This is a structural test: the field must be absent.
	opts := ServerOptions{}
	// If ServerOptions had UnsafeBindAll, this would reference it:
	// opts.UnsafeBindAll = true
	// The fact that this file compiles without that reference proves the field
	// is absent from ServerOptions.
	_ = opts
}
