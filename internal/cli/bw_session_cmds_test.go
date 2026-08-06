package cli_test

// bw_session_cmds_test.go — H5 CLI-level coverage for `bw lock` / `bw
// status` (the parts of the session-orchestration surface that don't
// require a real terminal / master-password prompt; `bw unlock`'s capture
// + cache + injection + expiry + invalidate logic is covered at the
// backend level in internal/backend/bw, since promptHidden reads
// os.Stdin.Fd() directly and can't be driven from an in-process test
// without a real pty).

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/cli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBWStatus_NoCache_ReportsAbsent(t *testing.T) {
	sessionDir := filepath.Join(t.TempDir(), "sessions")
	t.Setenv("KEYLATCH_BW_SESSION_DIR", sessionDir)

	root := cli.NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"bw", "status"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "No cached Bitwarden session")
	assert.Contains(t, stdout.String(), "keylatch bw unlock")
}

func TestBWStatus_ValidCache_ReportsExpiry(t *testing.T) {
	sessionDir := filepath.Join(t.TempDir(), "sessions")
	t.Setenv("KEYLATCH_BW_SESSION_DIR", sessionDir)

	env := func(k string) string {
		if k == "KEYLATCH_BW_SESSION_DIR" {
			return sessionDir
		}
		return ""
	}
	require.NoError(t, bw.SaveSession(env, "canary-cli-token", time.Hour))

	root := cli.NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"bw", "status"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "valid until")
	assert.NotContains(t, stdout.String(), "canary-cli-token", "token must never be printed by `bw status`")
	assert.NotContains(t, stderr.String(), "canary-cli-token")
}

func TestBWStatus_ExpiredCache_ReportsExpired(t *testing.T) {
	sessionDir := filepath.Join(t.TempDir(), "sessions")
	t.Setenv("KEYLATCH_BW_SESSION_DIR", sessionDir)

	env := func(k string) string {
		if k == "KEYLATCH_BW_SESSION_DIR" {
			return sessionDir
		}
		return ""
	}
	require.NoError(t, bw.SaveSession(env, "canary-cli-token-2", 1*time.Millisecond))
	time.Sleep(20 * time.Millisecond)

	root := cli.NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"bw", "status"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "EXPIRED")
	assert.NotContains(t, stdout.String(), "canary-cli-token-2")
}

func TestBWLock_ClearsCache(t *testing.T) {
	sessionDir := filepath.Join(t.TempDir(), "sessions")
	t.Setenv("KEYLATCH_BW_SESSION_DIR", sessionDir)

	env := func(k string) string {
		if k == "KEYLATCH_BW_SESSION_DIR" {
			return sessionDir
		}
		return ""
	}
	require.NoError(t, bw.SaveSession(env, "canary-to-clear", time.Hour))

	root := cli.NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"bw", "lock"})

	err := root.Execute()
	require.NoError(t, err)
	assert.Contains(t, stdout.String(), "cleared")

	status, statErr := bw.StatSession(env)
	require.NoError(t, statErr)
	assert.False(t, status.Present, "bw lock must clear the cached session")
}

func TestBWLock_NoCache_NotAnError(t *testing.T) {
	sessionDir := filepath.Join(t.TempDir(), "sessions")
	t.Setenv("KEYLATCH_BW_SESSION_DIR", sessionDir)

	root := cli.NewRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"bw", "lock"})

	err := root.Execute()
	require.NoError(t, err)
}
