package runner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// gatewayTypedMode is the KEYLATCH_RUNTIME value injected into the child env.
const gatewayTypedMode = string(runtime.RuntimeGatewayTyped)

// ErrGatewayNotRunning is returned when the gateway_typed or gateway_sdk driver
// cannot reach the gateway server.
var ErrGatewayNotRunning = errors.New("runner: gateway is not running — run 'keylatch gateway up' first")

// GatewayTypedServerStarter is an alias for GatewayServerStarter, preserved for
// backward compatibility with external test code that references this name.
//
// Deprecated: use GatewayServerStarter directly.
type GatewayTypedServerStarter = GatewayServerStarter

// gatewayTypedDriver mints a scoped session token, injects KEYLATCH_GATEWAY_URL
// and KEYLATCH_GATEWAY_TOKEN into the child environment, and execs the subprocess.
// The provider API key is NOT injected into the child environment.
type gatewayTypedDriver struct {
	server         GatewayServerStarter
	signingKey     []byte
	tokenStorePath string
	// settings holds the resolved operating-mode effective settings.
	// A zero-value settings struct disables all optional subsystems.
	settings runtime.EffectiveSettings
	// auditEmitter is optional; when non-nil canary events are emitted via it.
	auditEmitter audit.Emitter
}

// NewGatewayTypedDriver returns a Driver that uses gateway_typed mode.
//
// server provides the gateway address (e.g. "127.0.0.1:7878").
// signingKey must be 32 bytes. tokenStorePath is the path for JWT persistence.
func NewGatewayTypedDriver(server GatewayServerStarter, signingKey []byte, tokenStorePath string) Driver {
	return &gatewayTypedDriver{
		server:         server,
		signingKey:     signingKey,
		tokenStorePath: tokenStorePath,
	}
}

// NewGatewayTypedDriverWithSettings returns a gatewayTypedDriver with operating-mode
// effective settings and an optional audit emitter (may be nil).
// Used when operating mode is resolved at run time.
func NewGatewayTypedDriverWithSettings(
	server GatewayServerStarter,
	signingKey []byte,
	tokenStorePath string,
	settings runtime.EffectiveSettings,
	emitter audit.Emitter,
) Driver {
	return &gatewayTypedDriver{
		server:         server,
		signingKey:     signingKey,
		tokenStorePath: tokenStorePath,
		settings:       settings,
		auditEmitter:   emitter,
	}
}

// Run implements Driver for gatewayTypedDriver.
//
// Steps:
//  1. Verify the gateway server address is set (liveness guard is caller-side).
//  2. Mint a scoped session token for the requested capability.
//  3. Build child environment: gateway URL + session token. No provider API key.
//  4. Launch subprocess with child env.
//  5. Return RuntimeReceipt.
func (d *gatewayTypedDriver) Run(ctx context.Context, req ExecRequest, tmpl registry.ConnectionTemplate) (RuntimeReceipt, error) {
	receipt := RuntimeReceipt{
		Runtime:         gatewayTypedMode,
		CredentialShape: string(runtime.DeliveryKeylatchSessionToken),
	}

	if len(req.Command) == 0 {
		receipt.PolicyDecision = "empty_command"
		return receipt, fmt.Errorf("gateway_typed driver: empty command")
	}

	// Step 1: verify gateway is running before any credential operation.
	if !d.server.Running() {
		receipt.PolicyDecision = "gateway_not_running"
		return receipt, ErrGatewayNotRunningStructured(tmpl.Provider, gatewayTypedMode)
	}

	// Step 2: mint a scoped session token.
	actor := req.Actor
	if actor == "" {
		actor = "typed_driver"
	}
	jwtStr, revoke, err := sessionToken(d.signingKey, d.tokenStorePath, actor, sessionCapabilities(tmpl, req.Capability), req.TTL)
	if err != nil {
		receipt.PolicyDecision = "token_mint_failed"
		return receipt, fmt.Errorf("gateway_typed driver: mint token: %w", err)
	}
	defer revoke()

	// Step 3: build child env: gateway URL + session token. No provider API key.
	// Strip provider keys declared in InjectionRules, then inject
	// gateway URL + session token. Provider API key must not reach the subprocess.
	addr := d.server.Addr()
	gatewayURL := "http://" + addr

	childEnv := gatewayTypedChildEnv(tmpl, gatewayURL, jwtStr, req.CleanEnv, req.ExtraEnvVars)
	childEnv = mergeEnvPairs(childEnv, req.LocalEnv)

	// Canary injection — when enabled, mint a canary token and inject it
	// into the child env. The token value is never logged; only metadata is emitted.
	secrets := [][]byte{[]byte(jwtStr)}
	if d.settings.CanaryInjectionEnabled {
		canaryToken, canaryErr := canary.BuildCanary(tmpl.Provider)
		if canaryErr == nil {
			secrets = append(secrets, []byte(canaryToken))
			envVar := canary.EnvVarName(tmpl.Provider)
			childEnv = appendOrReplace(childEnv, envVar, canaryToken)
			// Emit audit event with metadata only — no token value.
			if d.auditEmitter != nil {
				_ = d.auditEmitter.Emit(ctx, audit.Event{
					Action:  audit.ActionCanaryInjected,
					Outcome: audit.OutcomeOK,
					Extra: map[string]any{
						"provider": tmpl.Provider,
						// Use HMAC'd form — never log raw actor IDs.
						"session_id_hmac": fmt.Sprintf("%x", sha256.Sum256([]byte(actor)))[:16],
					},
				})
			}
		}
	}

	// Step 4: launch subprocess.
	stdout := req.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := req.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	//nolint:gosec // G204: command allowlist enforcement is caller-side (DispatchRunner.Run).
	cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
	cmd.Env = childEnv
	guard := newOutputGuard(stdout, stderr, req.WorkingDir, req.FileScan, secrets...)
	cmd.Stdout = guard.Stdout()
	cmd.Stderr = guard.Stderr()
	if req.Stdin != nil {
		cmd.Stdin = req.Stdin
	} else {
		cmd.Stdin = os.Stdin
	}
	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}

	start := time.Now()
	runErr := cmd.Run()
	receipt.TTL = time.Since(start)
	receipt.LeakedFiles = guard.Finish()

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			receipt.ExitCode = exitErr.ExitCode()
			return receipt, nil
		}
		receipt.PolicyDecision = "process_error"
		return receipt, fmt.Errorf("gateway_typed driver: subprocess: %w", runErr)
	}

	receipt.PolicyDecision = "allowed"
	return receipt, nil
}

// gatewayTypedChildEnv builds the child environment for gateway_typed mode:
// provider key variables are stripped, KEYLATCH_* configuration is dropped and
// only the gateway URL, session token and runtime name are set.
func gatewayTypedChildEnv(tmpl registry.ConnectionTemplate, gatewayURL, jwtStr string, cleanEnv bool, extra []string) []string {
	return GatewaySessionEnv(runtime.RuntimeGatewayTyped, tmpl, gatewayURL, jwtStr).Apply(os.Environ(), cleanEnv, extra)
}
