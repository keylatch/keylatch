package cli_test

// keyring_passphrase_test.go — S-FIND-12
//
// Tests asserting that KEYLATCH_PASSPHRASE is not accepted by keyring init
// and that keyring init requires a TTY or stdin pipe.

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stdinToDevNull replaces os.Stdin with /dev/null for the duration of the test.
// /dev/null is neither a TTY nor a named pipe, so readPassphrase must reject it.
// Returns a cleanup function registered via t.Cleanup automatically.
func stdinToDevNull(t *testing.T) {
	t.Helper()
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err, "open /dev/null for stdin redirect")
	origStdin := os.Stdin
	os.Stdin = devNull
	t.Cleanup(func() {
		os.Stdin = origStdin
		_ = devNull.Close()
	})
}

// TestKeyringInit_PassphraseEnvIgnored verifies that setting KEYLATCH_PASSPHRASE
// and running keyring init without a TTY or stdin pipe exits with an error
// containing "not supported" (S-FIND-12). The env-var value must never appear
// in any output — proving the env var was never read as a passphrase source.
func TestKeyringInit_PassphraseEnvIgnored(t *testing.T) {
	const envPassphrase = "super-secret-DEADBEEF-passphrase"
	t.Setenv("KEYLATCH_PASSPHRASE", envPassphrase)

	// stdin is /dev/null — not a TTY, not a named pipe.
	stdinToDevNull(t)

	root := cli.NewRootCommand()
	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	root.SetOut(io.Discard)
	root.SetArgs([]string{"keyring", "init"})

	execErr := root.Execute()

	// Must fail because stdin is neither TTY nor pipe.
	require.Error(t, execErr, "keyring init must fail when stdin is /dev/null (no TTY, no pipe)")

	// Verify rejection came from the stdin guard (UsageError), not a passphrase attempt.
	assert.Contains(t, execErr.Error(), "UsageError",
		"rejection must come from stdin guard, not a passphrase attempt")

	combined := execErr.Error() + " " + errBuf.String()

	// Error must mention the canonical rejection reason.
	assert.True(t,
		strings.Contains(combined, "not supported"),
		"error must mention 'not supported' (KEYLATCH_PASSPHRASE rejection); got: %q", combined)

	// The secret value from KEYLATCH_PASSPHRASE must not leak into any output.
	assert.NotContains(t, errBuf.String(), envPassphrase,
		"KEYLATCH_PASSPHRASE value must not appear in stderr output")
	assert.NotContains(t, execErr.Error(), envPassphrase,
		"KEYLATCH_PASSPHRASE value must not appear in error string")
}

// TestKeyringInit_RequiresTTYOrStdin verifies that keyring init exits with an
// error when stdin is neither a TTY nor a pipe, and that the error message
// references TTY or stdin pipe as the expected input source (S-FIND-12).
func TestKeyringInit_RequiresTTYOrStdin(t *testing.T) {
	// stdin is /dev/null — neither a TTY nor a named pipe.
	stdinToDevNull(t)

	root := cli.NewRootCommand()
	root.SetOut(io.Discard)
	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	root.SetArgs([]string{"keyring", "init"})

	execErr := root.Execute()

	// Must return an error.
	require.Error(t, execErr, "keyring init must fail without TTY or stdin pipe")

	// Verify rejection came from the stdin guard (UsageError), not a passphrase attempt.
	assert.Contains(t, execErr.Error(), "UsageError",
		"rejection must come from stdin guard, not a passphrase attempt")

	combined := execErr.Error() + " " + errBuf.String()

	// Error must reference TTY, stdin pipe, or "not supported".
	assert.True(t,
		strings.Contains(combined, "TTY") ||
			strings.Contains(combined, "stdin pipe") ||
			strings.Contains(combined, "not supported"),
		"error must reference TTY/stdin pipe requirement; got: %q", combined)
}
