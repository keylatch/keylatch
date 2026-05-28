package runner

import (
	"context"
	"strings"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// Driver is the per-mode execution handler. Each runtime mode registers one
// Driver in a DispatchRunner. Run must emit a RuntimeReceipt on every path
// including errors (S-RM-9).
type Driver interface {
	Run(ctx context.Context, req ExecRequest, tmpl registry.ConnectionTemplate) (RuntimeReceipt, error)
}

// GatewayServerStarter is the unified interface used by both gateway_typed and
// gateway_sdk drivers to obtain the gateway listen address and check liveness.
// It replaces the formerly duplicate GatewayTypedServerStarter and
// GatewaySDKServerStarter interfaces.
type GatewayServerStarter interface {
	// Addr returns the gateway listen address (e.g. "127.0.0.1:7878").
	Addr() string
	// Running returns true when the gateway process is reachable.
	Running() bool
}

// GuardFunc is a hook called before any credential read. Return true to block.
// The implementation lives in internal/cli/guard_runtime.go; it is injected
// here via DispatchRunner.Guard to avoid a circular import.
type GuardFunc func(mode runtime.RuntimeMode, approvalJWT string) (block bool)

// DispatchRunner is the production Runner that calls runtime.Resolve(), applies
// the LLM session guard, and dispatches to the per-mode Driver.
type DispatchRunner struct {
	// Drivers maps RuntimeMode strings to their Driver implementations.
	Drivers map[string]Driver
	// Guard is the LLM session guard hook. When nil, all sessions are permitted — only set nil in tests.
	Guard GuardFunc
}

// Dispatcher is the contract for the new ExecRequest-based dispatch path.
type Dispatcher interface {
	Run(ctx context.Context, req ExecRequest) (RuntimeReceipt, error)
}

var _ Dispatcher = DispatchRunner{}

// Run implements the dispatch pipeline:
//  1. LLM session guard — returns ErrGuardDenied if blocked.
//  2. registry lookup to get the provider template.
//  3. runtime.Resolve — selects the runtime mode.
//  4. Driver lookup — returns ErrUnknownRuntime if no driver is registered.
//  5. Driver.Run — executes the subprocess.
//
// A RuntimeReceipt is returned on every path including errors (S-RM-9).
func (d DispatchRunner) Run(ctx context.Context, req ExecRequest) (RuntimeReceipt, error) {
	cap := req.Capability
	if cap == "" {
		cap = "inject"
	}
	empty := RuntimeReceipt{Provider: req.ConnectionSlug, Capability: cap}

	// Step 1: LLM session guard before any credential read.
	mode := runtime.RuntimeMode(req.Runtime)
	if d.Guard != nil {
		if blocked := d.Guard(mode, req.ApprovalJWT); blocked {
			empty.PolicyDecision = "guard_denied"
			return empty, ErrGuardDenied
		}
	}

	// Step 2: provider template lookup.
	tmpl, err := registry.Get(req.ConnectionSlug)
	if err != nil {
		empty.PolicyDecision = "provider_not_found"
		return empty, err
	}

	// Step 2b: allowlist enforcement (S0-9). Mirrors ProcessRunner matching rules:
	//   - Exact match:   exe == allowed
	//   - Dot-suffix:    exe starts with allowed+"." (e.g. "python3.12" matches "python3")
	//   - Path-suffix:   exe starts with allowed+"/" (e.g. "python3/bin" matches "python3")
	// HasPrefix without the suffix guard is intentionally NOT used.
	// ExtraAllowedPrefixes (from ExecRequest) are prepended for this invocation only
	// to support the CLI --allow flag for human-only sessions.
	effectivePrefixes := append(req.ExtraAllowedPrefixes, tmpl.AllowedCommandPrefixes...)
	if len(req.Command) == 0 || len(effectivePrefixes) == 0 {
		empty.PolicyDecision = "command_not_allowed"
		return empty, ErrCommandNotAllowed
	}
	exe := req.Command[0]
	matched := false
	for _, prefix := range effectivePrefixes {
		trimmed := strings.TrimRight(prefix, " ")
		if exe == trimmed ||
			(strings.HasPrefix(exe, trimmed) && len(exe) > len(trimmed) && (exe[len(trimmed)] == '.' || exe[len(trimmed)] == '/')) {
			matched = true
			break
		}
	}
	if !matched {
		empty.PolicyDecision = "command_not_allowed"
		return empty, ErrCommandNotAllowed
	}

	// Step 3: resolve runtime mode.
	resolveReq := runtime.ResolveRequest{
		RequestedMode:  mode,
		ConnectionSlug: req.ConnectionSlug,
	}
	decision, err := runtime.Resolve(ctx, resolveReq, tmpl)
	if err != nil {
		empty.PolicyDecision = "mode_not_supported"
		return empty, err
	}

	// Step 4: driver lookup.
	driver, ok := d.Drivers[string(decision.Mode)]
	if !ok {
		empty.Runtime = string(decision.Mode)
		empty.PolicyDecision = "unknown_runtime"
		return empty, ErrUnknownRuntime
	}

	// Step 5: delegate to driver.
	receipt, runErr := driver.Run(ctx, req, tmpl)
	receipt.Provider = req.ConnectionSlug
	receipt.Runtime = string(decision.Mode)
	if receipt.Capability == "" {
		receipt.Capability = cap
	}
	if receipt.CredentialShape == "" {
		receipt.CredentialShape = string(decision.CredentialShape)
	}

	return receipt, runErr
}
