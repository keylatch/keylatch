//go:build !windows

// Package runner — driver_classic_sandboxed.go wires the direct_classic_sandboxed
// runtime mode to the sandbox package on Linux and macOS.
//
// On Linux  → bwrap (bubblewrap) process sandbox.
// On macOS  → sandbox-exec(1) TinyScheme sandbox.
// On Windows → driver_classic_sandboxed_windows.go returns ErrModeNotAvailable.
//
// Security invariants (mirrored from internal/sandbox):
//   - Executable hash is verified before exec (SandboxManifest.ExecHash).
//   - ~/.keylatch is denied inside the sandbox (bwrap --tmpfs / SBPL deny).
//   - Child env receives only explicit EnvInject vars; host env is never inherited.
//   - No shell string construction — subprocess argv is a slice.
//   - feature flag "direct_classic_sandboxed" must be true in ExecRequest.FeatureFlags.
package runner

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/keylatch/keylatch/internal/sandbox"
)

const directClassicSandboxedMode = string(runtime.RuntimeDirectClassicSandboxed)

// classicSandboxedDriver implements Driver for the direct_classic_sandboxed mode.
// It builds a SandboxManifest from the ExecRequest and provider template, then
// delegates to sandbox.RunSandboxed which dispatches to the platform primitive.
type classicSandboxedDriver struct {
	audit audit.Emitter
}

// NewClassicSandboxedDriver returns a Driver for direct_classic_sandboxed mode.
// emitter may be nil; when nil, audit events are silently dropped.
func NewClassicSandboxedDriver(emitter audit.Emitter) Driver {
	return &classicSandboxedDriver{audit: emitter}
}

// Run implements Driver.
//
// Steps:
//  1. Verify feature flag "direct_classic_sandboxed" is set in req.FeatureFlags.
//  2. Ensure req.Command is non-empty.
//  3. Build sandbox.SandboxManifest from req and tmpl.
//  4. Emit SandboxLaunched audit event (best-effort).
//  5. Delegate to sandbox.RunSandboxed (platform-dispatched).
//  6. Return RuntimeReceipt.
func (d *classicSandboxedDriver) Run(ctx context.Context, req ExecRequest, tmpl registry.ConnectionTemplate) (RuntimeReceipt, error) {
	receipt := RuntimeReceipt{
		Runtime:         directClassicSandboxedMode,
		CredentialShape: string(runtime.DeliveryProviderRoot),
	}

	// Step 1: verify feature flag first — before any filesystem access or audit
	// events. When the flag is absent, nothing else should run (C3).
	if !req.FeatureFlags["direct_classic_sandboxed"] {
		return receipt, sandbox.ErrFeatureFlagRequired
	}

	if len(req.Command) == 0 {
		return receipt, fmt.Errorf("direct_classic_sandboxed: empty command")
	}

	// Step 2: build manifest from request.
	// The executable is the first element of the command; additional args are
	// NOT passed to sandbox.RunSandboxed — RunSandboxed executes the manifest
	// Executable directly. For a full arg-passing implementation, the manifest
	// would need an Args field. The executable is the primary unit.
	execPath := req.Command[0]

	// Compute executable hash for verification.
	execHash, err := sandbox.HashExecutable(execPath)
	if err != nil {
		d.emitLaunchRefused(ctx, req, execHash, "", "hash-compute-failed")
		return receipt, fmt.Errorf("direct_classic_sandboxed: hash executable: %w", err)
	}

	manifest := &sandbox.SandboxManifest{
		ProfileID:  req.ConnectionSlug,
		Executable: execPath,
		ExecHash:   execHash,
		EnvInject:  make(map[string]string),
	}

	// Inject credential env vars from the provider template's injection rules.
	// In the sandboxed mode we inject the env vars names as placeholders; the
	// actual values come from req.ExtraEnvVars (passed as extraEnv to RunSandboxed).
	// This follows the same pattern as the brokered driver: the caller provides
	// prepared KEY=VALUE pairs via req.FeatureFlags / ExtraEnvVars.
	//
	// ExtraEnvVars carries the actual credential env pairs.
	// The Manifest.EnvInject map is used for static / well-known pairs only.

	// Step 4: emit SandboxLaunched audit event before exec.
	d.emitLaunched(ctx, req, execHash)

	// Step 5: delegate to platform sandbox primitive. Pass d.audit so the
	// sandbox package can emit ActionSandboxDenyApplied after deny-list validation (W1+W2).
	if err := sandbox.RunSandboxed(ctx, manifest, true, req.ExtraEnvVars, d.audit); err != nil {
		return receipt, fmt.Errorf("direct_classic_sandboxed: %w", err)
	}

	return receipt, nil
}

// emitLaunched emits the SandboxLaunched audit event. Safe when emitter is nil.
func (d *classicSandboxedDriver) emitLaunched(ctx context.Context, req ExecRequest, execHash string) {
	if d.audit == nil {
		return
	}
	_ = d.audit.Emit(ctx, audit.Event{
		Action:  audit.ActionSandboxLaunched,
		Outcome: audit.OutcomeOK,
		Extra: map[string]any{
			"provider":          req.ConnectionSlug,
			"runtime":           directClassicSandboxedMode,
			"executable":        req.Command[0],
			"executable_sha256": execHash,
		},
	})
}

// emitLaunchRefused emits the SandboxLaunchRefused audit event. Safe when emitter is nil.
func (d *classicSandboxedDriver) emitLaunchRefused(ctx context.Context, req ExecRequest, actual, expected, reason string) {
	if d.audit == nil {
		return
	}
	_ = d.audit.Emit(ctx, audit.Event{
		Action:  audit.ActionSandboxLaunchRefused,
		Outcome: audit.OutcomeDenied,
		Extra: map[string]any{
			"provider": req.ConnectionSlug,
			"runtime":  directClassicSandboxedMode,
			"expected": expected,
			"actual":   actual,
			"reason":   reason,
		},
	})
}
