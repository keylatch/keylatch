//go:build !linux && !darwin

package sandbox

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
)

// RunSandboxed is a stub for unsupported platforms (e.g., Windows).
// It always returns ErrModeNotAvailable with a descriptive message.
//
// On Windows: use 'direct_classic' or 'gateway_typed' instead.
// Sandbox execution is not supported in Keylatch 1.0.0 on this platform.
func RunSandboxed(_ context.Context, _ *SandboxManifest, _ bool, _ []string, _ audit.Emitter) error {
	return fmt.Errorf("sandbox: unsupported platform — sandboxed execution is not available. Use 'direct_classic' or 'gateway_typed' instead")
}
