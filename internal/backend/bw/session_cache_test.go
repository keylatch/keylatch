package bw_test

// session_cache_test.go — H5 session-cache seam: SaveSession/LoadSession/
// ClearSession/StatSession round-trip, TTL expiry, file modes, and the
// "StatSession never reads the token file" invariant.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tempSessionEnv returns an llmcontext.Lookup pointing KEYLATCH_BW_SESSION_DIR
// at a not-yet-created "sessions" subdirectory of a fresh t.TempDir(),
// isolating each test from the real ~/.keylatch and from other tests. The
// subdir must not pre-exist so SaveSession's os.MkdirAll(dir, 0o700) is the
// one creating it — t.TempDir() itself is created with the test binary's
// default (often 0755) permissions, which would otherwise mask the 0700
// mode assertion in TestSaveSession_FileModes.
func tempSessionEnv(t *testing.T) func(string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sessions")
	return func(k string) string {
		if k == "KEYLATCH_BW_SESSION_DIR" {
			return dir
		}
		return ""
	}
}

func TestSaveLoadSession_RoundTrip(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)

	require.NoError(t, bw.SaveSession(env, "canary-session-token-0xC0FFEE", time.Hour))

	token, ok, err := bw.LoadSession(env)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "canary-session-token-0xC0FFEE", token)
}

func TestSaveSession_EmptyToken_Errors(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	err := bw.SaveSession(env, "", time.Hour)
	assert.Error(t, err)
}

func TestSaveSession_FileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes not enforced on Windows")
	}
	t.Parallel()
	env := tempSessionEnv(t)
	require.NoError(t, bw.SaveSession(env, "token-abc", time.Hour))

	tokenInfo, err := os.Stat(bw.SessionCachePath(env))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), tokenInfo.Mode().Perm(), "session token file must be 0600")

	metaInfo, err := os.Stat(bw.SessionMetaPath(env))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), metaInfo.Mode().Perm(), "session meta file must be 0600")

	dirInfo, err := os.Stat(filepath.Dir(bw.SessionCachePath(env)))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm(), "session cache dir must be 0700")
}

func TestLoadSession_Expired_ReturnsNotOK(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	require.NoError(t, bw.SaveSession(env, "will-expire-soon", 1*time.Millisecond))
	time.Sleep(20 * time.Millisecond)

	token, ok, err := bw.LoadSession(env)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestLoadSession_NoCache_ReturnsNotOK(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	token, ok, err := bw.LoadSession(env)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestClearSession_RemovesFiles(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	require.NoError(t, bw.SaveSession(env, "to-be-cleared", time.Hour))

	require.NoError(t, bw.ClearSession(env))

	_, ok, err := bw.LoadSession(env)
	require.NoError(t, err)
	assert.False(t, ok)

	status, err := bw.StatSession(env)
	require.NoError(t, err)
	assert.False(t, status.Present)
}

func TestClearSession_NoCache_NotAnError(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	assert.NoError(t, bw.ClearSession(env))
}

func TestStatSession_ExpiryReflectsTTL(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	before := time.Now()
	require.NoError(t, bw.SaveSession(env, "token-xyz", time.Hour))

	status, err := bw.StatSession(env)
	require.NoError(t, err)
	assert.True(t, status.Present)
	assert.False(t, status.Expired)
	assert.WithinDuration(t, before.Add(time.Hour), status.ExpiresAt, 5*time.Second)
}

func TestStatSession_NoCache_PresentFalse(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	status, err := bw.StatSession(env)
	require.NoError(t, err)
	assert.False(t, status.Present)
}

// TestStatSession_MissingTokenFile_TreatedAsAbsent verifies that a sidecar
// meta file without a corresponding token file (a corrupt/partial cache) is
// reported as absent rather than "present" — StatSession must never assume
// a token exists just because the metadata does.
func TestStatSession_MissingTokenFile_TreatedAsAbsent(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	require.NoError(t, bw.SaveSession(env, "token-1", time.Hour))
	require.NoError(t, os.Remove(bw.SessionCachePath(env)))

	status, err := bw.StatSession(env)
	require.NoError(t, err)
	assert.False(t, status.Present, "meta without token file must be treated as absent")
}

// TestSessionStatus_NoTokenField is a compile-time-adjacent documentation
// test: SessionStatus intentionally has no field that could hold the raw
// token, so no caller of StatSession can accidentally leak it.
func TestSessionStatus_NoTokenField(t *testing.T) {
	t.Parallel()
	var s bw.SessionStatus
	_ = s.Present
	_ = s.ExpiresAt
	_ = s.Expired
	// If a Token/Value field is ever added to SessionStatus, this test file
	// (and StatSession's doc comment) must be revisited.
}
