package file_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileBackend_ZeroKeyring_ZeroesDEKs verifies L2: ZeroKeyring() zeroes the
// attached keyring's DEK bytes, so a subsequent Get() against the SAME
// backend instance fails (AEAD auth failure) rather than returning
// plaintext, even though the manifest entry still exists.
func TestFileBackend_ZeroKeyring_ZeroesDEKs(t *testing.T) {
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.XChaCha20Poly1305)
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	require.NoError(t, err)
	defer fb.Close() //nolint:errcheck

	path := "default/zero/test"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}
	require.NoError(t, fb.Set(context.Background(), path, []byte("secret-value"), meta))

	// Sanity: readable before zeroing.
	got, _, err := fb.Get(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret-value"), got)

	fb.ZeroKeyring()

	// After zeroing, the manifest entry still exists but decryption must fail.
	_, _, err = fb.Get(context.Background(), path)
	require.Error(t, err, "Get after ZeroKeyring must fail — DEK bytes are zeroed")
}

// TestFileBackend_ZeroKeyring_NoKeyringIsNoop verifies ZeroKeyring is a safe
// no-op on a backend opened without a keyring (file.Open, not
// file.OpenWithKeyring).
func TestFileBackend_ZeroKeyring_NoKeyringIsNoop(t *testing.T) {
	dir := t.TempDir()
	fb, err := file.Open(file.Options{Dir: dir})
	require.NoError(t, err)
	defer fb.Close() //nolint:errcheck

	assert.NotPanics(t, func() { fb.ZeroKeyring() })
}

// TestFileBackend_Close_DoesNotZeroKeyring verifies Close() alone does NOT
// zero the keyring (dispatch.Select's per-process singleton caching relies
// on this: an intermediate existence-check Close() must not corrupt the DEK
// for later reuse in the same process). Only explicit ZeroKeyring() zeroes.
func TestFileBackend_Close_DoesNotZeroKeyring(t *testing.T) {
	dir := t.TempDir()
	kr, _ := buildKeyring(t, dir, envelope.XChaCha20Poly1305)
	fb, err := file.OpenWithKeyring(file.Options{Dir: dir}, kr)
	require.NoError(t, err)

	path := "default/close/test"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}
	require.NoError(t, fb.Set(context.Background(), path, []byte("secret-value"), meta))

	require.NoError(t, fb.Close())

	// Still readable after Close() — Close is a no-op w.r.t. the keyring.
	got, _, err := fb.Get(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret-value"), got)

	fb.ZeroKeyring()
	_, _, err = fb.Get(context.Background(), path)
	require.Error(t, err, "Get after ZeroKeyring must fail")
}
