package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// directBrokeredMode is the KEYLATCH_RUNTIME value injected into the child env.
const directBrokeredMode = string(runtime.RuntimeDirectBrokered)

// canonicalSecretPath builds the vault lookup path for a credential field
// using the canonical four-segment format: namespace/category/provider/field.
//
// v1.0.0 uses the canonical format exclusively.
// No backward-compat read from "default/connections/..." — v1.0.0 has no existing users.
func canonicalSecretPath(namespace, category, provider, field string) string {
	if category == "" {
		category = "ai" // safe default for provider templates that predate the category field
	}
	return fmt.Sprintf("%s/%s/%s/%s", namespace, category, provider, field)
}

// ErrUnsupportedRuntime is returned when a template does not have the
// required runtime support configuration for the requested driver.
var ErrUnsupportedRuntime = errors.New("runner: template does not support this runtime mode")

// BrokerExchanger is the minimal broker interface the brokered driver needs.
// This avoids taking a hard dependency on *broker.BrokerImpl.
type BrokerExchanger interface {
	Exchange(ctx context.Context, actor, sessionID, provider, capability, namespace string) (broker.ExchangeResult, error)
}

// brokeredDriver reads the root credential from vault, exchanges it for a
// short-lived token via the broker, injects it into the child environment,
// and execs the subprocess. Root credential bytes are zeroed immediately
// after Exchange returns.
type brokeredDriver struct {
	vault  backend.Backend
	broker BrokerExchanger
	audit  audit.Emitter
}

// NewBrokeredDriver returns a Driver that uses vault for credential storage
// and broker for short-lived token exchange.
func NewBrokeredDriver(vault backend.Backend, b BrokerExchanger, emitter audit.Emitter) Driver {
	return &brokeredDriver{vault: vault, broker: b, audit: emitter}
}

// Run implements Driver for brokeredDriver.
//
// Steps:
//  1. Verify tmpl.RuntimeSupport has BrokerSupport configured.
//  2. Fetch root credential from vault via tmpl.InjectionRules[0].SecretRef path.
//  3. Call broker.Exchange; zero root credential immediately after.
//  4. Build child env: inherited + child-env vars + KEYLATCH_RUNTIME.
//  5. Launch subprocess.
//  6. Emit ActionBrokerExchange audit event.
//  7. Return RuntimeReceipt.
func (d *brokeredDriver) Run(ctx context.Context, req ExecRequest, tmpl registry.ConnectionTemplate) (RuntimeReceipt, error) {
	receipt := RuntimeReceipt{
		Runtime:         directBrokeredMode,
		CredentialShape: string(runtime.DeliveryProviderEphemeral),
	}

	if len(req.Command) == 0 {
		return receipt, fmt.Errorf("direct_brokered: empty command")
	}

	// Step 1: verify broker support is configured.
	if tmpl.RuntimeSupport.Preferred != registry.RuntimeDirectBrokered {
		hasSupport := false
		for _, m := range tmpl.RuntimeSupport.Supported {
			if m == registry.RuntimeDirectBrokered {
				hasSupport = true
				break
			}
		}
		if !hasSupport {
			return receipt, ErrUnsupportedRuntime
		}
	}

	// Step 2: fetch root credential from vault.
	if len(tmpl.InjectionRules) == 0 {
		return receipt, fmt.Errorf("direct_brokered: template has no injection rules")
	}
	vaultPath := canonicalSecretPath("default", tmpl.Category, req.ConnectionSlug, tmpl.InjectionRules[0].Source)
	// Inject audit emitter so vault.Get can emit ActionRead events.
	if d.audit != nil {
		ctx = audit.WithEmitter(ctx, d.audit)
	}
	rootCredential, _, err := d.vault.Get(ctx, vaultPath)
	if err != nil {
		if errors.Is(err, backend.ErrNotFound) {
			return receipt, fmt.Errorf("direct_brokered: credential %q not found for %q: %w",
				tmpl.InjectionRules[0].Source, req.ConnectionSlug, backend.ErrNotFound)
		}
		return receipt, fmt.Errorf("direct_brokered: read credential: %w", err)
	}
	// Step 3: zero root credential after Exchange returns.
	defer zeroSlice(rootCredential)

	// Exchange root credential for a short-lived token.
	actor := req.Actor
	if actor == "" {
		actor = "direct_brokered"
	}
	namespace := "default"

	// The broker's Exchange takes actor, sessionID, provider, capability, namespace.
	// We derive sessionID from the ExecRequest or use a constant for non-session runs.
	sessionID := req.ConnectionSlug + "/" + actor

	exchangeResult, exchErr := d.broker.Exchange(ctx, actor, sessionID, req.ConnectionSlug, req.Capability, namespace)
	if exchErr != nil {
		return receipt, fmt.Errorf("direct_brokered: broker exchange: %w", exchErr)
	}
	tokenBytes := exchangeResult.TokenBytes()
	defer zeroSlice(tokenBytes)

	// Step 4: build child env.
	// direct_brokered runs in a trusted local process context. Inheriting
	// os.Environ() is intentional: the brokered token overwrites the primary
	// credential env var. KEYLATCH_* configuration vars are stripped via
	// FilterChildEnv before the subprocess sees the environment —
	// the only KEYLATCH_* var re-injected is KEYLATCH_RUNTIME so the child
	// process can identify the current runtime mode.
	parentEnv := os.Environ()

	// Inject short-lived token via the first injection rule's env var.
	// Build the final env BEFORE filtering so that the token value itself is
	// not inadvertently stripped (it doesn't start with KEYLATCH_).
	parentEnv = append(parentEnv, tmpl.InjectionRules[0].EnvVar+"="+string(tokenBytes))

	// Inject any additional injection rules.
	for i := 1; i < len(tmpl.InjectionRules); i++ {
		// For multi-rule templates, only the primary credential is brokered.
		// Additional rules inject an empty string deliberately: this shadows any
		// parent-env value for the secondary credential env var, ensuring it does
		// not leak into the subprocess even though it was not brokered.
		// direct_brokered does not support multi-credential brokering.
		parentEnv = append(parentEnv, tmpl.InjectionRules[i].EnvVar+"=")
	}

	// Strip all KEYLATCH_* vars from the child env; re-inject only
	// KEYLATCH_RUNTIME so the child can identify its runtime mode.
	// When CleanEnv is requested, start from a minimal base env
	// instead of the full parent env.
	var env []string
	if req.CleanEnv {
		env = runtime.CleanBaseEnv(parentEnv, req.ExtraEnvVars...)
		// CleanBaseEnv already strips everything — inject KEYLATCH_RUNTIME.
		env = append(env, "KEYLATCH_RUNTIME="+directBrokeredMode)
	} else {
		env = runtime.FilterChildEnv(parentEnv)
		env = append(env, "KEYLATCH_RUNTIME="+directBrokeredMode)
	}

	// Step 5: launch subprocess.
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
	cmd.Env = env
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

	runErr := cmd.Run()

	// Step 6: emit audit event.
	d.emitAudit(ctx, req, tmpl, &exchangeResult)

	// Step 7: emit receipt.
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			receipt.ExitCode = exitErr.ExitCode()
			return receipt, nil
		}
		return receipt, fmt.Errorf("direct_brokered: exec: %w", runErr)
	}
	return receipt, nil
}

// emitAudit emits a broker exchange audit event. Safe when audit emitter is nil.
func (d *brokeredDriver) emitAudit(ctx context.Context, req ExecRequest, _ registry.ConnectionTemplate, result *broker.ExchangeResult) {
	if d.audit == nil {
		return
	}
	ev := audit.Event{
		Action:  audit.ActionBrokerExchange,
		Outcome: audit.OutcomeOK,
		Extra: map[string]any{
			"provider":          req.ConnectionSlug,
			"actor_hmac":        req.Actor, // caller is expected to pass HMAC'd actor ID
			"capability":        req.Capability,
			"ttl_seconds":       int64(result.TTLRemaining.Seconds()),
			"exchange_strategy": string(result.ExchangeType),
		},
	}
	_ = d.audit.Emit(ctx, ev)
}

// zeroSlice overwrites a byte slice with zeros. Unlike the file-level zeroBytes
// in handler.go, this variant is local to runner and handles nil slices.
func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
