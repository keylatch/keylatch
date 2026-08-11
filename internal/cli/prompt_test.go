package cli

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFakePromptHidden replaces promptHiddenFn for the duration of the test
// and restores the original on cleanup. This is the seam every real
// promptHidden call site (bw unlock, connect custom, set, backup passphrase,
// setup) can now be exercised through without a real TTY/pty.
func withFakePromptHidden(t *testing.T, value []byte, err error) {
	t.Helper()
	orig := promptHiddenFn
	t.Cleanup(func() { promptHiddenFn = orig })
	promptHiddenFn = func() ([]byte, error) { return value, err }
}

func TestPromptHidden_ReturnsInjectedValue(t *testing.T) {
	withFakePromptHidden(t, []byte("s3cr3t"), nil)

	got, err := promptHidden("Password")
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t"), got)
}

func TestPromptHidden_PropagatesReaderError(t *testing.T) {
	readErr := errors.New("reading password: inappropriate ioctl for device")
	withFakePromptHidden(t, nil, readErr)

	got, err := promptHidden("Password")
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Equal(t, readErr, err)
}
