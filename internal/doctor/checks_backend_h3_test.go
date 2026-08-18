package doctor_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selectBackend overwrites the bootstrapped config's Backend field.
func selectBackend(t *testing.T, env func(string) string, backend string) {
	t.Helper()
	cfgPath := paths.Config(env)
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	cfg.Backend = backend
	require.NoError(t, config.Save(cfgPath, cfg))
}

// findCheck returns the Status with the given name, or fails the test.
func findCheck(t *testing.T, report doctor.Report, name string) doctor.Status {
	t.Helper()
	for _, s := range report.Checks {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("check %q not found in report", name)
	return doctor.Status{}
}

// TestDoctor_BackendBW_NotSelected_NoWarn is the H3 regression test: a
// merely-installed bw CLI must not warn when bw is not the selected backend.
func TestDoctor_BackendBW_NotSelected_NoWarn(t *testing.T) {
	_, env := bootstrappedHome(t) // default backend is "file"

	probe := newMockProbe()
	probe.found["bw"] = "/usr/local/bin/bw"

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.bw")
	assert.False(t, s.Warn, "bw installed but not selected must not warn")
	assert.Contains(t, s.Detail, "backend not selected")
	assert.NotContains(t, s.Detail, "session=unknown", "fabricated session literal must be gone")
}

// TestDoctor_BackendBW_Selected_Warns verifies bw still warns (asking for
// BW_SESSION) when it IS the selected backend.
func TestDoctor_BackendBW_Selected_Warns(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "bw")

	probe := newMockProbe()
	probe.found["bw"] = "/usr/local/bin/bw"

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.bw")
	assert.True(t, s.Warn, "bw selected without a session must still warn")
	assert.NotContains(t, s.Detail, "session=unknown", "fabricated session literal must be gone")
}

// TestDoctor_BackendOP_NotSelected_NoWarn mirrors the bw case for op (H3).
func TestDoctor_BackendOP_NotSelected_NoWarn(t *testing.T) {
	_, env := bootstrappedHome(t) // default backend is "file"

	probe := newMockProbe()
	probe.found["op"] = "/usr/local/bin/op"

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.op")
	assert.False(t, s.Warn, "op installed but not selected must not warn")
	assert.Contains(t, s.Detail, "backend not selected")
	assert.NotContains(t, s.Detail, "signed_in=unknown", "fabricated signed_in literal must be gone")
}

// TestDoctor_BackendOP_Selected_Warns verifies op still warns (asking to
// sign in) when it IS the selected backend.
func TestDoctor_BackendOP_Selected_Warns(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "op")

	probe := newMockProbe()
	probe.found["op"] = "/usr/local/bin/op"

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.op")
	assert.True(t, s.Warn, "op selected without a session must still warn")
	assert.NotContains(t, s.Detail, "signed_in=unknown", "fabricated signed_in literal must be gone")
}
