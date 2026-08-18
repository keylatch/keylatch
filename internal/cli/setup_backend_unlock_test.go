package cli

// setup_backend_unlock_test.go covers the setup [2/5] backend-setup
// additions for bw and op: checkOPAuthReady (pure subprocess probe) and
// setupUnlockBW's dispatch/backend-resolution paths. The password-entry
// step itself is exercised via the promptHiddenFn seam (prompt_test.go) —
// term.ReadPassword's raw-mode terminal read has no io.Reader-level
// substitute, so tests inject at that seam rather than faking a real TTY.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFakeBin writes an executable shell script named `name` (exiting with
// exitCode) into a fresh temp dir and prepends that dir to PATH for the
// duration of the test (t.Setenv, auto-restored). Mirrors the stub pattern
// in daemon_darwin_test.go.
func writeFakeBin(t *testing.T, name string, exitCode int) {
	t.Helper()
	binDir := t.TempDir()
	script := filepath.Join(binDir, name)
	content := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	require.NoError(t, os.WriteFile(script, []byte(content), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// isolatePATH points PATH at an empty temp dir so no real op/bw/etc. on the
// host machine can be found — needed because dev/CI machines commonly have
// both installed, which would otherwise make the "binary not found" cases
// non-deterministic.
func isolatePATH(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

func TestCheckOPAuthReady_TokenSet_SkipsBinaryCheck(t *testing.T) {
	isolatePATH(t) // no `op` on PATH at all — token presence must short-circuit
	env := func(k string) string {
		if k == "OP_SERVICE_ACCOUNT_TOKEN" {
			return "ops_fake_token_value"
		}
		return ""
	}
	err := checkOPAuthReady(context.Background(), env)
	assert.NoError(t, err)
}

func TestCheckOPAuthReady_NoToken_NoBinary_ReturnsNotFound(t *testing.T) {
	isolatePATH(t)
	env := func(string) string { return "" }
	err := checkOPAuthReady(context.Background(), env)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "op CLI not found on PATH")
}

func TestCheckOPAuthReady_NoToken_WhoamiSucceeds_ReturnsNil(t *testing.T) {
	writeFakeBin(t, "op", 0)
	env := func(string) string { return "" }
	err := checkOPAuthReady(context.Background(), env)
	assert.NoError(t, err)
}

func TestCheckOPAuthReady_NoToken_WhoamiFails_ReturnsNotSignedIn(t *testing.T) {
	writeFakeBin(t, "op", 1)
	env := func(string) string { return "" }
	err := checkOPAuthReady(context.Background(), env)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not signed in")
}

func TestSetupUnlockBW_NoBinary_ReturnsClearGuidance(t *testing.T) {
	isolatePATH(t)
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	c := &cobra.Command{}
	err := setupUnlockBW(c, context.Background(), llmcontext.DefaultLookup)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bitwarden CLI not available")
	assert.Contains(t, err.Error(), "brew install bitwarden-cli")
}

func TestSetupUnlockBW_BinaryPresent_NoTTY_FailsAtPasswordPrompt(t *testing.T) {
	writeFakeBin(t, "bw", 0)
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	c := &cobra.Command{}
	err := setupUnlockBW(c, context.Background(), llmcontext.DefaultLookup)
	// dispatch/backend resolution must succeed (bw binary found, type
	// assertion to *bw.BitwardenBackend holds) and the function must fail
	// specifically at the password prompt — not earlier, not by panicking,
	// and not by silently "succeeding" — when go test's stdin isn't a TTY.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read master password")
}

// writeFakeBWUnlock writes a `bw` stub that responds to `unlock --raw` with
// token on stdout and exit 0 — enough for BitwardenBackend.Unlock to return
// a real (fake) session token.
func writeFakeBWUnlock(t *testing.T, token string) {
	t.Helper()
	binDir := t.TempDir()
	script := filepath.Join(binDir, "bw")
	content := fmt.Sprintf("#!/bin/sh\necho %q\n", token)
	require.NoError(t, os.WriteFile(script, []byte(content), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestSetupUnlockBW_PasswordProvided_UnlocksAndCachesSession exercises the
// full success path using the promptHiddenFn seam — previously untestable,
// since promptHidden had no injection point and every setupUnlockBW test
// could only reach the "no TTY" failure just before this point.
func TestSetupUnlockBW_PasswordProvided_UnlocksAndCachesSession(t *testing.T) {
	writeFakeBWUnlock(t, "s.fake-session-token-abc123")
	withFakePromptHidden(t, []byte("correct-horse-battery-staple"), nil)

	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	t.Setenv("KEYLATCH_BW_SESSION_DIR", filepath.Join(configDir, "sessions"))
	dispatch.ClearCached()
	t.Cleanup(dispatch.ClearCached)

	var stdout bytes.Buffer
	c := &cobra.Command{}
	c.SetOut(&stdout)

	err := setupUnlockBW(c, context.Background(), llmcontext.DefaultLookup)
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "Bitwarden vault unlocked; session cached")

	cached, ok, loadErr := bw.LoadSession(llmcontext.DefaultLookup)
	require.NoError(t, loadErr)
	require.True(t, ok, "session must be cached after a successful unlock")
	assert.Equal(t, "s.fake-session-token-abc123", cached)
}
