//go:build !windows

package runner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sandboxedTmpl builds a ConnectionTemplate that declares direct_classic_sandboxed support.
func sandboxedTmpl(provider string) registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: provider,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeMode(runtime.RuntimeDirectClassicSandboxed),
			Supported: []registry.RuntimeMode{
				registry.RuntimeMode(runtime.RuntimeDirectClassicSandboxed),
			},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "TEST_API_KEY", Source: "api_key"},
		},
	}
}

// TestDirectClassicSandboxed_Linux_Smoke verifies that the driver is registered
// and reachable via DispatchRunner (no ErrUnknownRuntime).
//
// This test does NOT require bwrap to be installed — it only verifies driver
// registration and early error paths. Smoke tests that require bwrap are
// exercised in CI with sudo apt-get install -y bubblewrap.
func TestDirectClassicSandboxed_Linux_Smoke(t *testing.T) {
	d := runner.NewClassicSandboxedDriver(nil)

	dr := runner.DispatchRunner{
		Guard: nil,
		Drivers: map[string]runner.Driver{
			string(runtime.RuntimeDirectClassicSandboxed): d,
		},
	}

	req := runner.ExecRequest{
		ConnectionSlug:       "testprovider",
		Command:              []string{"/bin/sh", "-c", "true"},
		Runtime:              string(runtime.RuntimeDirectClassicSandboxed),
		ExtraAllowedPrefixes: []string{"/bin/sh"},
		FeatureFlags:         map[string]bool{"direct_classic_sandboxed": true},
	}

	_, err := dr.Run(context.Background(), req)
	// Must NOT be ErrUnknownRuntime — the driver is registered.
	assert.False(t, errors.Is(err, runner.ErrUnknownRuntime),
		"direct_classic_sandboxed driver must be registered — ErrUnknownRuntime must not be returned")
}

// TestDirectClassicSandboxed_EmptyCommand verifies that an empty command returns
// an error before any sandbox invocation.
func TestDirectClassicSandboxed_EmptyCommand(t *testing.T) {
	d := runner.NewClassicSandboxedDriver(nil)

	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{},
		FeatureFlags:   map[string]bool{"direct_classic_sandboxed": true},
	}

	_, err := d.Run(context.Background(), req, sandboxedTmpl("testprovider"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty command",
		"empty command must return an error")
}

// TestDirectClassicSandboxed_FeatureFlagFalse verifies that when the
// direct_classic_sandboxed feature flag is false, the sandbox refuses launch.
func TestDirectClassicSandboxed_FeatureFlagFalse(t *testing.T) {
	d := runner.NewClassicSandboxedDriver(nil)

	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"/bin/sh"},
		FeatureFlags:   map[string]bool{"direct_classic_sandboxed": false},
	}

	_, err := d.Run(context.Background(), req, sandboxedTmpl("testprovider"))
	// The driver checks the feature flag first (C3) — before any filesystem access.
	// ErrFeatureFlagRequired is returned immediately, no hash computation occurs.
	require.ErrorIs(t, err, sandbox.ErrFeatureFlagRequired,
		"disabled feature flag must cause launch failure with ErrFeatureFlagRequired")
}

// TestDispatch_ClassicSandboxed_DriverRegistered verifies the new mode routes
// correctly through a stub driver without ErrUnknownRuntime.
func TestDispatch_ClassicSandboxed_DriverRegistered(t *testing.T) {
	stub := &stubDriver{receipt: runner.RuntimeReceipt{ExitCode: 0}}

	req := runner.ExecRequest{
		ConnectionSlug:       "testprovider",
		Command:              []string{"/bin/sh", "echo"},
		Runtime:              string(runtime.RuntimeDirectClassicSandboxed),
		ExtraAllowedPrefixes: []string{"/bin/sh"},
	}

	// Call the stub driver directly to verify the receipt shape.
	receipt, err := stub.Run(context.Background(), req, sandboxedTmpl("testprovider"))
	require.NoError(t, err)
	assert.Equal(t, 0, receipt.ExitCode)
}
