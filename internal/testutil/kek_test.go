package testutil

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKEK_RoundTripsAndRejectsTampering(t *testing.T) {
	k := NewKEK(t)
	assert.Equal(t, "testutil-aead", k.ID())
	assert.Equal(t, "passphrase", k.Type())

	plain := []byte("data encryption key")
	wrapped, err := k.Wrap(plain)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(wrapped, plain), "wrapped value must not contain the plaintext")

	again, err := k.Wrap(plain)
	require.NoError(t, err)
	assert.NotEqual(t, wrapped, again, "each wrap uses a fresh nonce")

	got, err := k.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, plain, got)

	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff
	_, err = k.Unwrap(tampered)
	require.Error(t, err)

	_, err = k.Unwrap([]byte("short"))
	require.Error(t, err)

	_, err = NewKEK(t).Unwrap(wrapped)
	require.Error(t, err, "a different key cannot unwrap")
}
