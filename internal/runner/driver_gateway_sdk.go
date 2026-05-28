package runner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// gatewaySdkMode is the KEYLATCH_RUNTIME value injected into the child env.
const gatewaySdkMode = string(runtime.RuntimeGatewaySDK)

// GatewaySDKServerStarter is an alias for GatewayServerStarter, preserved for
// backward compatibility with external test code that references this name.
//
// Deprecated: use GatewayServerStarter directly.
type GatewaySDKServerStarter = GatewayServerStarter

// gatewaySdkDriver runs the child process with OPENAI_BASE_URL (or the
// provider-equivalent SDK env var) pointing to the local keylatch gateway.
// The provider API key is NOT injected into the child environment.
type gatewaySdkDriver struct {
	server GatewayServerStarter
	key    []byte
	store  string
	// settings holds the resolved operating-mode effective settings (EPIC-17).
	settings     runtime.EffectiveSettings
	auditEmitter audit.Emitter
}

// NewGatewaySDKDriver returns a Driver that uses gateway_sdk mode.
//
// server provides the gateway address (e.g. "127.0.0.1:7878").
// signingKey must be 32 bytes. tokenStorePath is the path for JWT persistence.
func NewGatewaySDKDriver(server GatewayServerStarter, signingKey []byte, tokenStorePath string) Driver {
	return &gatewaySdkDriver{server: server, key: signingKey, store: tokenStorePath}
}

// NewGatewaySDKDriverWithSettings returns a gatewaySdkDriver with operating-mode
// effective settings and an optional audit emitter (may be nil).
// EPIC-17: used when operating mode is resolved at run time.
func NewGatewaySDKDriverWithSettings(
	server GatewayServerStarter,
	signingKey []byte,
	tokenStorePath string,
	settings runtime.EffectiveSettings,
	emitter audit.Emitter,
) Driver {
	return &gatewaySdkDriver{
		server:       server,
		key:          signingKey,
		store:        tokenStorePath,
		settings:     settings,
		auditEmitter: emitter,
	}
}

// Run implements Driver for gatewaySdkDriver.
//
// Steps:
//  1. Mint a scoped session token for the requested capability.
//  2. Build child environment: base URL + session token. No provider API key.
//  3. Launch subprocess with child env.
//  4. Return RuntimeReceipt.
func (d *gatewaySdkDriver) Run(ctx context.Context, req ExecRequest, tmpl registry.ConnectionTemplate) (RuntimeReceipt, error) {
	receipt := RuntimeReceipt{
		Provider:        req.ConnectionSlug,
		Capability:      req.Capability,
		Runtime:         gatewaySdkMode,
		CredentialShape: string(runtime.RuntimeGatewaySDK),
	}

	if len(req.Command) == 0 {
		receipt.PolicyDecision = "empty_command"
		return receipt, fmt.Errorf("gateway_sdk driver: empty command")
	}

	// Step 1a: verify gateway is running before any Addr() call.
	if !d.server.Running() {
		receipt.PolicyDecision = "gateway_not_running"
		return receipt, ErrGatewayNotRunningStructured(tmpl.Provider, gatewaySdkMode)
	}

	// Step 1: Mint a scoped session token with the provider capability.
	actor := req.Actor
	if actor == "" {
		actor = "sdk_driver"
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	cap := tmpl.Provider + "." + req.Capability
	if req.Capability == "" || req.Capability == "inject" {
		// Default: grant all gateway actions for this provider.
		cap = tmpl.Provider + ".*"
	}

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        actor,
		Capabilities: []string{cap},
		TTL:          ttl,
		LLMSession:   false,
		SigningKey:   d.key,
		StorePath:    d.store,
	})
	if err != nil {
		receipt.PolicyDecision = "token_mint_failed"
		return receipt, fmt.Errorf("gateway_sdk driver: mint token: %w", err)
	}

	// Step 2: Build child env: base URL + session token. No provider key.
	// Rules (T-08-01, §15.1):
	//   1. Strip provider API key vars declared in InjectionRules.
	//   2. Strip all KEYLATCH_* configuration vars (FilterChildEnv).
	//   3. Re-inject only gateway vars + KEYLATCH_RUNTIME.
	denyVars := make(map[string]struct{}, len(tmpl.InjectionRules))
	for _, rule := range tmpl.InjectionRules {
		denyVars[rule.EnvVar] = struct{}{}
	}
	raw := os.Environ()
	stripped := make([]string, 0, len(raw))
	for _, e := range raw {
		idx := strings.IndexByte(e, '=')
		if idx < 0 {
			stripped = append(stripped, e)
			continue
		}
		if _, skip := denyVars[e[:idx]]; !skip {
			stripped = append(stripped, e)
		}
	}
	// T-08-01: strip remaining KEYLATCH_* vars; re-inject only gateway token + runtime.
	// T-08-02: when CleanEnv is requested, use CleanBaseEnv for a minimal start.
	var childEnv []string
	if req.CleanEnv {
		childEnv = runtime.CleanBaseEnv(stripped, req.ExtraEnvVars...)
	} else {
		childEnv = runtime.FilterChildEnv(stripped,
			"KEYLATCH_GATEWAY_TOKEN",
			"KEYLATCH_RUNTIME",
		)
	}
	baseURL := "http://" + d.server.Addr()
	childEnv = appendOrReplace(childEnv, sdkBaseURLVar(tmpl), baseURL)
	childEnv = appendOrReplace(childEnv, "KEYLATCH_GATEWAY_TOKEN", jwtStr)
	childEnv = appendOrReplace(childEnv, "KEYLATCH_RUNTIME", gatewaySdkMode)

	// EPIC-17: canary injection — when enabled, mint a canary token and inject it
	// into the child env. The token value is never logged; only metadata is emitted.
	if d.settings.CanaryInjectionEnabled {
		canaryToken, canaryErr := canary.BuildCanary(tmpl.Provider)
		if canaryErr == nil {
			envVar := canary.EnvVarName(tmpl.Provider)
			childEnv = appendOrReplace(childEnv, envVar, canaryToken)
			if d.auditEmitter != nil {
				_ = d.auditEmitter.Emit(ctx, audit.Event{
					Action:  audit.ActionCanaryInjected,
					Outcome: audit.OutcomeOK,
					Extra: map[string]any{
						"provider": tmpl.Provider,
						// Use HMAC'd form — never log raw actor IDs (S5-2 / FIND2-012).
						"session_id_hmac": fmt.Sprintf("%x", sha256.Sum256([]byte(actor)))[:16],
					},
				})
			}
		}
	}

	// Step 3: Launch subprocess.
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
	cmd.Stdout = stdout
	cmd.Stderr = stderr
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
	receipt.TTL = time.Since(start) // stores actual execution duration (not a cap)

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			receipt.ExitCode = exitErr.ExitCode()
			return receipt, nil
		}
		receipt.PolicyDecision = "process_error"
		return receipt, fmt.Errorf("gateway_sdk driver: subprocess: %w", runErr)
	}

	receipt.PolicyDecision = "allowed"
	return receipt, nil
}

// sdkBaseURLVar returns the SDK-specific environment variable name for the
// gateway base URL. Defaults to OPENAI_BASE_URL for unknown providers.
func sdkBaseURLVar(tmpl registry.ConnectionTemplate) string {
	switch tmpl.Provider {
	case "openai":
		return "OPENAI_BASE_URL"
	case "anthropic":
		return "ANTHROPIC_BASE_URL"
	case "openrouter":
		return "OPENROUTER_BASE_URL"
	default:
		// Convention: <PROVIDER_UPPER>_BASE_URL (e.g. "mistral" → "MISTRAL_BASE_URL")
		return strings.ToUpper(strings.ReplaceAll(tmpl.Provider, "-", "_")) + "_BASE_URL"
	}
}

// appendOrReplace sets key=value in env, replacing an existing entry if present.
func appendOrReplace(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = key + "=" + value
			return env
		}
	}
	return append(env, key+"="+value)
}
