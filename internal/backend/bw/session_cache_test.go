package bw_test

// session_cache_test.go — session-cache seam: SaveSession/LoadSession/
// ClearSession/StatSession round-trip, TTL bounds, file modes, sealing under
// the KEK (no plaintext on disk) and the "StatSession never reads the token
// file" invariant.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/testutil"
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
	env, k := tempSessionEnv(t), testutil.NewKEK(t)

	require.NoError(t, bw.SaveSession(env, k, "canary-session-token-0xC0FFEE", time.Hour))

	token, ok, err := bw.LoadSession(env, k)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "canary-session-token-0xC0FFEE", token)
}

func TestNoPlaintextSessionFile(t *testing.T) {
	t.Parallel()
	env, k := tempSessionEnv(t), testutil.NewKEK(t)
	const token = "canary-session-token-never-on-disk-0xBADA55"
	require.NoError(t, bw.SaveSession(env, k, token, time.Hour))

	dir := filepath.Dir(bw.SessionCachePath(env))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		assert.False(t, strings.Contains(string(data), token), "%s must not contain the session token", e.Name())
	}
	assert.NoFileExists(t, bw.LegacySessionPath(env), "no plaintext session file is written")

	other := testutil.NewKEK(t)
	_, ok, err := bw.LoadSession(env, other)
	assert.Error(t, err, "a different key cannot open the sealed session")
	assert.False(t, ok)
}

func TestSessionTTL(t *testing.T) {
	t.Parallel()
	env, k := tempSessionEnv(t), testutil.NewKEK(t)

	require.NoError(t, bw.SaveSession(env, k, "token-default-ttl", 0))
	status, err := bw.StatSession(env)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(time.Hour), status.ExpiresAt, 5*time.Second, "the default lifetime is one hour")
	assert.Equal(t, time.Hour, bw.DefaultSessionTTL)

	require.NoError(t, bw.SaveSession(env, k, "token-max-ttl", bw.MaxSessionTTL))
	err = bw.SaveSession(env, k, "token-too-long", bw.MaxSessionTTL+time.Second)
	assert.ErrorIs(t, err, bw.ErrSessionTTLTooLong)
	token, ok, err := bw.LoadSession(env, k)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "token-max-ttl", token, "a refused save leaves the previous session")
}

func TestLockRemovesLegacyFile(t *testing.T) {
	t.Parallel()
	env, k := tempSessionEnv(t), testutil.NewKEK(t)
	dir := filepath.Dir(bw.SessionCachePath(env))
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(bw.LegacySessionPath(env), []byte("old-plaintext-token"), 0o600))

	status, err := bw.StatSession(env)
	require.NoError(t, err)
	assert.True(t, status.LegacyPlaintext)
	assert.False(t, status.Present)

	require.NoError(t, bw.ClearSession(env))
	assert.NoFileExists(t, bw.LegacySessionPath(env))

	// Saving a sealed session also retires a leftover plaintext file.
	require.NoError(t, os.WriteFile(bw.LegacySessionPath(env), []byte("old-plaintext-token"), 0o600))
	require.NoError(t, bw.SaveSession(env, k, "new-sealed-token", time.Hour))
	assert.NoFileExists(t, bw.LegacySessionPath(env))
}

func TestSaveSession_EmptyToken_Errors(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	err := bw.SaveSession(env, testutil.NewKEK(t), "", time.Hour)
	assert.Error(t, err)
}

func TestSaveSession_FileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes not enforced on Windows")
	}
	t.Parallel()
	env := tempSessionEnv(t)
	require.NoError(t, bw.SaveSession(env, testutil.NewKEK(t), "token-abc", time.Hour))

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
	env, k := tempSessionEnv(t), testutil.NewKEK(t)
	require.NoError(t, bw.SaveSession(env, k, "will-expire-soon", 1*time.Millisecond))
	time.Sleep(20 * time.Millisecond)

	token, ok, err := bw.LoadSession(env, k)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestLoadSession_NoCache_ReturnsNotOK(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	token, ok, err := bw.LoadSession(env, testutil.NewKEK(t))
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, token)
}

func TestClearSession_RemovesFiles(t *testing.T) {
	t.Parallel()
	env, k := tempSessionEnv(t), testutil.NewKEK(t)
	require.NoError(t, bw.SaveSession(env, k, "to-be-cleared", time.Hour))

	require.NoError(t, bw.ClearSession(env))

	_, ok, err := bw.LoadSession(env, k)
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
	require.NoError(t, bw.SaveSession(env, testutil.NewKEK(t), "token-xyz", time.Hour))

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
	require.NoError(t, bw.SaveSession(env, testutil.NewKEK(t), "token-1", time.Hour))
	require.NoError(t, os.Remove(bw.SessionCachePath(env)))

	status, err := bw.StatSession(env)
	require.NoError(t, err)
	assert.False(t, status.Present, "meta without token file must be treated as absent")
}

func TestStatSession_CorruptMeta_IsAnError(t *testing.T) {
	t.Parallel()
	env := tempSessionEnv(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(bw.SessionMetaPath(env)), 0o700))
	require.NoError(t, os.WriteFile(bw.SessionMetaPath(env), []byte("{not json"), 0o600))
	_, err := bw.StatSession(env)
	assert.Error(t, err)
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
	_ = s.LegacyPlaintext
	// If a Token/Value field is ever added to SessionStatus, this test file
	// (and StatSession's doc comment) must be revisited.
}
