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

// stubDriver is an in-process Driver implementation for unit tests.
type stubDriver struct {
	receipt runner.RuntimeReceipt
	err     error
}

func (s *stubDriver) Run(_ context.Context, _ runner.ExecRequest, _ registry.ConnectionTemplate) (runner.RuntimeReceipt, error) {
	return s.receipt, s.err
}

// resolvedMode is the runtime mode that the real openrouter template resolves to.
// openrouter prefers gateway_sdk and that is what Resolve() returns.
const openrouterResolvedMode = string(runtime.RuntimeGatewaySDK)

// TestDispatchRunner_GuardDeny verifies ErrGuardDenied is returned when the
// guard hook blocks the request.
func TestDispatchRunner_GuardDeny(t *testing.T) {
	dr := runner.DispatchRunner{
		Guard: func(_ runtime.RuntimeMode, _ string) bool { return true },
	}
	req := runner.ExecRequest{ConnectionSlug: "openrouter"}
	receipt, err := dr.Run(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrGuardDenied))
	assert.Equal(t, "guard_denied", receipt.PolicyDecision)
}

// TestDispatchRunner_UnknownRuntimeMode verifies ErrUnknownRuntime is returned
// when the resolved mode has no registered Driver.
func TestDispatchRunner_UnknownRuntimeMode(t *testing.T) {
	// No drivers registered; resolved mode (gateway_sdk) has no handler.
	dr := runner.DispatchRunner{
		Guard:   func(_ runtime.RuntimeMode, _ string) bool { return false },
		Drivers: map[string]runner.Driver{},
	}
	// "node" is in openrouter's allowlist so the allowlist check passes.
	req := runner.ExecRequest{ConnectionSlug: "openrouter", Command: []string{"node", "index.js"}}
	receipt, err := dr.Run(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrUnknownRuntime),
		"no registered driver must return ErrUnknownRuntime, not panic")
	assert.Equal(t, openrouterResolvedMode, receipt.Runtime)
}

// TestDispatchRunner_DriverReceiptPropagated verifies the Driver's RuntimeReceipt
// is returned to the caller with provider and runtime fields populated.
func TestDispatchRunner_DriverReceiptPropagated(t *testing.T) {
	stub := &stubDriver{
		receipt: runner.RuntimeReceipt{ExitCode: 0},
	}
	dr := runner.DispatchRunner{
		Guard: func(_ runtime.RuntimeMode, _ string) bool { return false },
		Drivers: map[string]runner.Driver{
			openrouterResolvedMode: stub,
		},
	}
	// "node" is in openrouter's allowlist so the allowlist check passes.
	req := runner.ExecRequest{ConnectionSlug: "openrouter", Capability: "inject", Command: []string{"node", "index.js"}}
	receipt, err := dr.Run(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "openrouter", receipt.Provider)
	assert.Equal(t, openrouterResolvedMode, receipt.Runtime)
	assert.Equal(t, "inject", receipt.Capability)
}

// TestDispatchRunner_DriverErrorPropagated verifies that a Driver error is
// returned alongside a populated RuntimeReceipt (S-RM-9).
func TestDispatchRunner_DriverErrorPropagated(t *testing.T) {
	driverErr := errors.New("driver: subprocess exec failed")
	stub := &stubDriver{
		receipt: runner.RuntimeReceipt{ExitCode: 1},
		err:     driverErr,
	}
	dr := runner.DispatchRunner{
		Guard: func(_ runtime.RuntimeMode, _ string) bool { return false },
		Drivers: map[string]runner.Driver{
			openrouterResolvedMode: stub,
		},
	}
	// "node" is in openrouter's allowlist so the allowlist check passes.
	req := runner.ExecRequest{ConnectionSlug: "openrouter", Command: []string{"node", "index.js"}}
	receipt, err := dr.Run(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, driverErr, err)
	// Receipt is still populated even on error (S-RM-9).
	assert.Equal(t, "openrouter", receipt.Provider)
	assert.Equal(t, 1, receipt.ExitCode)
}

// TestDispatchRunner_GuardPassAllowsExecution verifies that when the guard
// passes, execution proceeds to the driver.
func TestDispatchRunner_GuardPassAllowsExecution(t *testing.T) {
	stub := &stubDriver{receipt: runner.RuntimeReceipt{ExitCode: 0}}
	dr := runner.DispatchRunner{
		Guard: func(_ runtime.RuntimeMode, _ string) bool { return false },
		Drivers: map[string]runner.Driver{
			openrouterResolvedMode: stub,
		},
	}
	// "node" is in openrouter's allowlist so the allowlist check passes.
	req := runner.ExecRequest{ConnectionSlug: "openrouter", Command: []string{"node", "index.js"}}
	_, err := dr.Run(context.Background(), req)
	require.NoError(t, err)
}

// TestDispatchRunner_AllowlistDenied verifies that ErrCommandNotAllowed is returned
// when the command does not match any entry in the template's AllowedCommandPrefixes.
// The openrouter template only allows "node" and "tsx" prefixes.
func TestDispatchRunner_AllowlistDenied(t *testing.T) {
	stub := &stubDriver{receipt: runner.RuntimeReceipt{ExitCode: 0}}
	dr := runner.DispatchRunner{
		Guard: func(_ runtime.RuntimeMode, _ string) bool { return false },
		Drivers: map[string]runner.Driver{
			openrouterResolvedMode: stub,
		},
	}
	// "bash" is not in openrouter's allowlist (node, tsx).
	req := runner.ExecRequest{
		ConnectionSlug: "openrouter",
		Command:        []string{"bash", "-c", "echo hi"},
	}
	receipt, err := dr.Run(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrCommandNotAllowed),
		"non-allowlisted command must return ErrCommandNotAllowed")
	assert.Equal(t, "command_not_allowed", receipt.PolicyDecision)
}

// TestDispatchRunner_NilGuardAllowsAll verifies that when Guard is nil, all
// sessions are permitted and execution proceeds to the driver.
func TestDispatchRunner_NilGuardAllowsAll(t *testing.T) {
	stub := &stubDriver{receipt: runner.RuntimeReceipt{ExitCode: 0}}
	dr := runner.DispatchRunner{
		Guard: nil, // nil Guard: all sessions are permitted — only for tests.
		Drivers: map[string]runner.Driver{
			openrouterResolvedMode: stub,
		},
	}
	// "node" is in openrouter's allowlist.
	req := runner.ExecRequest{
		ConnectionSlug: "openrouter",
		Command:        []string{"node", "index.js"},
	}
	receipt, err := dr.Run(context.Background(), req)
	require.NoError(t, err, "nil Guard must not return ErrGuardDenied")
	assert.Equal(t, "openrouter", receipt.Provider)
}
