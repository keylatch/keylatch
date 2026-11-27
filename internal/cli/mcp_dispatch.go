package cli

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
)

// newMCPDispatcher builds what keylatch_run runs commands through: the
// gateway runtimes only, so the child gets a scoped session token and never
// the credential, the session guard, connection policy decided for an agent
// caller, and the audit log, which must be writable. The returned function closes the audit log.
func newMCPDispatcher() (runner.Dispatcher, func(), error) {
	env := llmcontext.DefaultLookup
	auditLog, cleanup, err := requireAuditLogger("mcp")
	if err != nil {
		return nil, nil, err
	}

	signingKey, keyErr := LoadGatewaySigningKey(env, false)
	if keyErr != nil {
		cleanup()
		return nil, nil, fmt.Errorf("the gateway signing key is not available: %w", keyErr)
	}
	gatewayAddr, err := gatewayRunAddr(env)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	gatewaySrv := &gatewayServerAdapter{addr: gatewayAddr, pidPath: paths.GatewayPID(env)}

	cfg, cfgErr := config.Load(paths.Config(env))
	if cfgErr != nil {
		cfg = config.Default()
	}
	opMode, _ := runtime.ResolveMode("", runtime.OperatingMode(cfg.Mode))
	settings := runtime.EffectiveSettingsForMode(opMode, mapCustomConfig(cfg.Custom))
	tokenStore := paths.GatewayTokens(env)
	emitter := audit.AsEmitter(auditLog)

	return mcpDispatchRunner(env, emitter, map[string]runner.Driver{
		string(runtime.RuntimeGatewayTyped): runner.NewGatewayTypedDriverWithSettings(gatewaySrv, signingKey, tokenStore, settings, nil),
		string(runtime.RuntimeGatewaySDK):   runner.NewGatewaySDKDriverWithSettings(gatewaySrv, signingKey, tokenStore, settings, nil),
	}), cleanup, nil
}

// mcpDispatchRunner wires the checks every MCP run goes through before a
// driver starts: the session guard, then connection policy via enforce.Decide.
func mcpDispatchRunner(env llmcontext.Lookup, emitter audit.Emitter, drivers map[string]runner.Driver) runner.DispatchRunner {
	return runner.DispatchRunner{
		Guard: runner.GuardFunc(func(m runtime.RuntimeMode, jwt string) bool {
			blocked, _ := GuardRuntime(m, jwt, env, nil)
			return blocked
		}),
		Audit:   emitter,
		Enforce: ciScopedEnforce(enforce.Decide),
		Drivers: drivers,
	}
}
