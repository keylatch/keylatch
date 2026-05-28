//go:build windows

package runner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDirectClassicSandboxed_Windows_ReturnsErrModeNotAvailable verifies that
// the Windows stub driver always returns ErrModeNotAvailable.
func TestDirectClassicSandboxed_Windows_ReturnsErrModeNotAvailable(t *testing.T) {
	d := runner.NewClassicSandboxedDriver(nil)

	req := runner.ExecRequest{
		ConnectionSlug: "testprovider",
		Command:        []string{"cmd.exe", "/c", "echo"},
		FeatureFlags:   map[string]bool{"direct_classic_sandboxed": true},
	}

	_, err := d.Run(context.Background(), req, registry.ConnectionTemplate{
		Provider: "testprovider",
		RuntimeSupport: registry.RuntimeSupport{
			Supported: []registry.RuntimeMode{registry.RuntimeMode(runtime.RuntimeDirectClassicSandboxed)},
		},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrModeNotAvailable),
		"Windows stub must return ErrModeNotAvailable for direct_classic_sandboxed")
}
