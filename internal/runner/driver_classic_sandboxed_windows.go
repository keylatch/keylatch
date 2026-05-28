//go:build windows

// Package runner — driver_classic_sandboxed_windows.go provides a stub Driver
// for the direct_classic_sandboxed mode on Windows.
//
// Windows does not have bwrap or sandbox-exec equivalents; the mode is declared
// but always returns ErrModeNotAvailable so CLI callers receive a clear error.
package runner

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

const directClassicSandboxedMode = string(runtime.RuntimeDirectClassicSandboxed)

// classicSandboxedDriver is the Windows stub for direct_classic_sandboxed.
type classicSandboxedDriver struct {
	audit audit.Emitter
}

// NewClassicSandboxedDriver returns the Windows stub Driver for
// direct_classic_sandboxed mode. It always returns ErrModeNotAvailable.
func NewClassicSandboxedDriver(emitter audit.Emitter) Driver {
	return &classicSandboxedDriver{audit: emitter}
}

// Run implements Driver on Windows.
// Always returns ErrModeNotAvailable — sandboxed execution requires bwrap or
// sandbox-exec which are not available on Windows.
func (d *classicSandboxedDriver) Run(_ context.Context, _ ExecRequest, _ registry.ConnectionTemplate) (RuntimeReceipt, error) {
	return RuntimeReceipt{
		Runtime:         directClassicSandboxedMode,
		CredentialShape: string(runtime.DeliveryProviderRoot),
		PolicyDecision:  "mode_not_available",
	}, fmt.Errorf("direct_classic_sandboxed: %w: sandboxed execution is not supported on Windows", ErrModeNotAvailable)
}
