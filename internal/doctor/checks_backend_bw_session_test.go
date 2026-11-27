package doctor_test

// checkBackendBWSession must recognize a
// valid cached session (from `keylatch bw unlock`) as equivalent to an
// ambient BW_SESSION env var, without ever exposing the cached token.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoctor_BWSession_NoEnvNoCache_Warns(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "bw")

	probe := newMockProbe()
	probe.found["bw"] = "/usr/local/bin/bw"

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.bw.session")
	assert.True(t, s.Warn)
	assert.Contains(t, s.Fix, "keylatch bw unlock")
}

func TestDoctor_BWSession_ValidCache_NoWarn(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "bw")
	require.NoError(t, bw.SaveSession(env, testutil.NewKEK(t), "canary-doctor-token", time.Hour))

	probe := newMockProbe()
	probe.found["bw"] = "/usr/local/bin/bw"

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.bw.session")
	assert.False(t, s.Warn, "a valid cached session must satisfy the session check without BW_SESSION set")
	assert.Contains(t, s.Detail, "cached session present")
	assert.NotContains(t, s.Detail, "canary-doctor-token", "doctor must never print the cached token")
}

func TestDoctor_BWSession_ExpiredCache_Warns(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "bw")
	require.NoError(t, bw.SaveSession(env, testutil.NewKEK(t), "canary-doctor-token-2", 1*time.Millisecond))
	time.Sleep(20 * time.Millisecond)

	probe := newMockProbe()
	probe.found["bw"] = "/usr/local/bin/bw"

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.bw.session")
	assert.True(t, s.Warn, "an expired cached session must not silence the warning")
	assert.Contains(t, s.Detail, "expired")
	assert.NotContains(t, s.Detail, "canary-doctor-token-2")
}

func TestDoctor_LeftoverPlaintextBWSessionFails(t *testing.T) {
	_, env := bootstrappedHome(t)

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: newMockProbe()})
	require.NoError(t, err)
	assert.True(t, findCheck(t, report, "backend.bw_session_file").OK, "no leftover file, no failure")

	require.NoError(t, os.MkdirAll(filepath.Dir(bw.LegacySessionPath(env)), 0o700))
	require.NoError(t, os.WriteFile(bw.LegacySessionPath(env), []byte("canary-legacy-session"), 0o600))
	report, err = doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: newMockProbe()})
	require.NoError(t, err)
	s := findCheck(t, report, "backend.bw_session_file")
	assert.False(t, s.OK, "a plaintext session file is a failure")
	assert.Contains(t, s.Fix, "keylatch bw lock")
	assert.NotContains(t, s.Detail, "canary-legacy-session")
}

func TestDoctor_BWSession_AmbientEnvStillWorks(t *testing.T) {
	tmp, baseEnv := bootstrappedHome(t)
	_ = tmp
	selectBackend(t, baseEnv, "bw")

	env := func(k string) string {
		if k == "BW_SESSION" {
			return "canary-ambient-session"
		}
		return baseEnv(k)
	}

	probe := newMockProbe()
	probe.found["bw"] = "/usr/local/bin/bw"

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.bw.session")
	assert.False(t, s.Warn)
	assert.NotContains(t, s.Detail, "canary-ambient-session", "doctor must never print BW_SESSION")
}
