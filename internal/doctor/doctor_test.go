package doctor_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/doctor"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProbe is a canned Probe for testing.
type mockProbe struct {
	found   map[string]string // bin -> path
	version map[string]string // path -> version string
}

func newMockProbe() *mockProbe {
	return &mockProbe{
		found:   make(map[string]string),
		version: make(map[string]string),
	}
}

func (m *mockProbe) Find(_ context.Context, bin string) (string, bool, error) {
	if p, ok := m.found[bin]; ok {
		return p, true, nil
	}
	return "", false, nil
}

func (m *mockProbe) Version(_ context.Context, path string) (string, error) {
	if v, ok := m.version[path]; ok {
		return v, nil
	}
	return "unknown", nil
}

var _ kexec.Probe = (*mockProbe)(nil)

// makeEnv builds a Lookup from a map, falling back to os.Getenv.
func makeEnv(overrides map[string]string) llmcontext.Lookup {
	return func(k string) string {
		if v, ok := overrides[k]; ok {
			return v
		}
		return ""
	}
}

// bootstrappedHome bootstraps a fresh HOME and returns the HOME dir and Lookup.
func bootstrappedHome(t *testing.T) (string, llmcontext.Lookup) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := makeEnv(map[string]string{"KEYLATCH_CONFIG_DIR": filepath.Join(tmp, ".keylatch")})
	fullEnv := func(k string) string {
		if v := env(k); v != "" {
			return v
		}
		if k == "HOME" {
			return tmp
		}
		return ""
	}
	_, err := bootstrap.Run(context.Background(), bootstrap.Options{Env: fullEnv})
	require.NoError(t, err)
	return tmp, fullEnv
}

func TestRun_FreshHome_OverallOK(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)
	// Print failing checks for diagnosis.
	for _, s := range report.Checks {
		if !s.OK {
			t.Logf("FAILING CHECK: %s: %s (fix: %s)", s.Name, s.Detail, s.Fix)
		}
	}
	assert.True(t, report.OverallOK, "bootstrapped HOME should have OverallOK=true")
	assert.NotEmpty(t, report.Version)
	assert.NotEmpty(t, report.Platform)
	assert.NotEmpty(t, report.CipherSuite)
}

func TestRun_JSONRoundTrip(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	b, err := json.Marshal(report)
	require.NoError(t, err)

	var roundTripped doctor.Report
	require.NoError(t, json.Unmarshal(b, &roundTripped))
	assert.Equal(t, report.OverallOK, roundTripped.OverallOK)
	assert.Equal(t, report.CipherSuite, roundTripped.CipherSuite)
}

func TestRun_RedactPaths(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose:     true,
		RedactPaths: true,
		Env:         env,
		Probe:       probe,
	})
	require.NoError(t, err)

	// With redact-paths, no absolute path starting with / should appear in Detail.
	for _, s := range report.Checks {
		if len(s.Detail) > 0 && s.Detail[0] == '/' {
			t.Errorf("check %q detail starts with / after redact: %q", s.Name, s.Detail)
		}
	}
}

func TestRun_FreshHome_NoPaths(t *testing.T) {
	// Run doctor on a fresh home with no bootstrap — should have failed path checks.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	env := func(k string) string {
		if k == "HOME" {
			return tmp
		}
		return ""
	}
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)
	// Path checks should fail.
	assert.False(t, report.OverallOK, "unbootstrapped HOME should have OverallOK=false")
}

func TestRun_CanaryNotInOutput(t *testing.T) {
	// S05-7: the canary must never appear in any check output.
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	// Write a config with the canary as an unknown field — Load rejects it, so
	// the config is read as default. But we verify the canary doesn't leak anyway.
	configDir := env("KEYLATCH_CONFIG_DIR")
	if configDir != "" {
		canaryConfig := filepath.Join(configDir, "config.json")
		_ = os.WriteFile(canaryConfig,
			[]byte(`{"version":1,"backend":"file","default_namespace":"default","audit":{"enabled":true,"max_size_bytes":5242880},"ui":{"bind":"127.0.0.1"},"KEYLATCH_CANARY_DO_NOT_LEAK_0xDEADBEEF":"canary"}`),
			0o600)
	}

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	b, err := json.Marshal(report)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "KEYLATCH_CANARY_DO_NOT_LEAK_0xDEADBEEF")
	assert.NotContains(t, string(b), "0xDEADBEEF")
}

func TestRun_VerboseFalse_OmitsOKChecks(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: false,
		Env:     env,
		Probe:   probe,
	})
	require.NoError(t, err)

	// In non-verbose mode, only warning or failing checks should be in Checks.
	for _, s := range report.Checks {
		assert.True(t, !s.OK || s.Warn,
			"non-verbose report should only contain !OK or Warn checks, got: %+v", s)
	}
}

func TestRun_CipherSuite(t *testing.T) {
	_, env := bootstrappedHome(t)
	probe := newMockProbe()
	report, err := doctor.Run(context.Background(), doctor.Options{Env: env, Probe: probe})
	require.NoError(t, err)
	// Default (non-FIPS) build must report xchacha20-poly1305.
	assert.Equal(t, "xchacha20-poly1305", report.CipherSuite)
	assert.False(t, report.FIPSBuild)
}
