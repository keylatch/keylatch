package cli

import (
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeZeroableBackend implements backend.Backend (via nil-embedding, only
// Close/ZeroKeyring are exercised by this test) and records whether each was
// called.
type fakeZeroableBackend struct {
	backend.Backend
	closed bool
	zeroed bool
}

func (f *fakeZeroableBackend) Close() error {
	f.closed = true
	return nil
}

func (f *fakeZeroableBackend) ZeroKeyring() {
	f.zeroed = true
}

// fakeNonZeroableBackend implements backend.Backend but has no ZeroKeyring
// method (mirrors non-file backends: keychain, bw, op, etc.).
type fakeNonZeroableBackend struct {
	backend.Backend
	closed bool
}

func (f *fakeNonZeroableBackend) Close() error {
	f.closed = true
	return nil
}

func TestCloseAndZeroBackend_CallsZeroKeyringWhenSupported(t *testing.T) {
	t.Parallel()
	fb := &fakeZeroableBackend{}
	err := closeAndZeroBackend(fb)
	require.NoError(t, err)
	assert.True(t, fb.closed, "Close must be called")
	assert.True(t, fb.zeroed, "ZeroKeyring must be called when the backend supports it")
}

func TestCloseAndZeroBackend_NoPanicWhenUnsupported(t *testing.T) {
	t.Parallel()
	fb := &fakeNonZeroableBackend{}
	assert.NotPanics(t, func() {
		err := closeAndZeroBackend(fb)
		require.NoError(t, err)
	})
	assert.True(t, fb.closed, "Close must still be called")
}
