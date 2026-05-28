package op_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/op"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	canaryOP = "KEYLATCH_CANARY_OP_0xDEADBEEF"
)

// loadFixture loads a testdata file relative to this test file.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "testdata")
	b, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err, "fixture %q must exist", name)
	return b
}

// TestRedaction_AdversarialStderr_CanaryAbsent verifies that when `op item get`
// returns stderr containing a token-shaped string (OP_SERVICE_ACCOUNT_TOKEN=<canary>),
// the canary never appears in the returned error message (S2-9).
func TestRedaction_AdversarialStderr_CanaryAbsent(t *testing.T) {
	fixture := loadFixture(t, "adversarial_stderr_service_account.txt")

	// Verify the fixture actually contains the canary (sanity check).
	require.Contains(t, string(fixture), canaryOP, "fixture must contain canary")

	key := strings.Join([]string{fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json"}, "|")
	runner := makeRunner(key, kexec.MockResponse{Stderr: fixture, ExitCode: 1})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)

	// S2-9: canary must not appear in the error message.
	assert.NotContains(t, err.Error(), canaryOP,
		"canary must not leak from adversarial stderr into error message")
	assert.NotContains(t, err.Error(), "OP_SERVICE_ACCOUNT_TOKEN",
		"OP_SERVICE_ACCOUNT_TOKEN must not leak into error message")
}

// TestRedaction_BiometricPrompt_HintOnly verifies that biometric-prompt markers
// in stderr are replaced with the user-facing hint, not echoed raw.
func TestRedaction_BiometricPrompt_HintOnly(t *testing.T) {
	biometricStderr := []byte("biometric prompt required; please authenticate with Touch ID")

	key := strings.Join([]string{fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json"}, "|")
	runner := makeRunner(key, kexec.MockResponse{Stderr: biometricStderr, ExitCode: 1})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)

	// Raw stderr must not appear in error, but typed error or hint may.
	assert.NotContains(t, err.Error(), "biometric prompt required")
}

// TestRedaction_AuthFailure_HintPresent verifies the hint text is present for
// auth-failure scenarios and raw stderr is absent.
func TestRedaction_AuthFailure_HintPresent(t *testing.T) {
	fixture := loadFixture(t, "auth_failure_stderr.txt")

	key := strings.Join([]string{fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json"}, "|")
	runner := makeRunner(key, kexec.MockResponse{Stderr: fixture, ExitCode: 1})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)

	assert.True(t, errors.Is(err, backend.ErrLocked))
	// Hint present.
	assert.Contains(t, err.Error(), "op signin")
	// Raw stderr absent (S2-9).
	assert.NotContains(t, err.Error(), "not currently signed in")
}

// TestRedaction_RecoveryCodes_Absent verifies that recovery codes in mocked
// stderr never appear in returned errors.
func TestRedaction_RecoveryCodes_Absent(t *testing.T) {
	recoverCodeStderr := []byte("Recovery code: ABCD-1234-EFGH-5678 -- please store this safely")

	key := strings.Join([]string{fakeOpBin, "item", "get", "openrouter", "--vault=Keylatch", "--format=json"}, "|")
	runner := makeRunner(key, kexec.MockResponse{Stderr: recoverCodeStderr, ExitCode: 1})

	b, err := op.Open(op.Options{Bin: fakeOpBin, Runner: runner, Vault: "Keylatch"})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "default/openrouter/api_key")
	require.Error(t, err)

	// Recovery code must not appear in error message.
	assert.NotContains(t, err.Error(), "ABCD-1234-EFGH-5678",
		"recovery code must not leak into error message")
	assert.NotContains(t, err.Error(), "Recovery code",
		"raw stderr content must not leak into error message")
}
