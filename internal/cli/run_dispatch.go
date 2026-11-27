package cli

import (
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
)

// runtimeGuard returns the LLM session guard injected into DispatchRunner.
func runtimeGuard() runner.GuardFunc {
	return func(m runtime.RuntimeMode, jwt string) bool {
		blocked, _ := GuardRuntime(m, jwt, llmcontext.DefaultLookup, nil)
		return blocked
	}
}

// newGatewayDrivers builds the gateway_typed and gateway_sdk drivers.
// A missing signing key is not fatal here: without one the gateway cannot have
// been initialized, so the drivers fail at Run with the gateway-not-running error.
func newGatewayDrivers(env llmcontext.Lookup, modeFlag string) (map[string]runner.Driver, error) {
	signingKey, _ := LoadGatewaySigningKey(env, false)
	tokenStorePath := paths.GatewayTokens(env)

	gatewayAddr, err := gatewayRunAddr(env)
	if err != nil {
		return nil, err
	}
	gatewaySrv := &gatewayServerAdapter{
		addr:    gatewayAddr,
		pidPath: paths.GatewayPID(env),
	}

	opCfg, cfgLoadErr := config.Load(paths.Config(env))
	if cfgLoadErr != nil {
		opCfg = config.Default()
	}
	opMode, _ := runtime.ResolveMode(modeFlag, runtime.OperatingMode(opCfg.Mode))
	opSettings := runtime.EffectiveSettingsForMode(opMode, mapCustomConfig(opCfg.Custom))

	return map[string]runner.Driver{
		string(runtime.RuntimeGatewayTyped): runner.NewGatewayTypedDriverWithSettings(gatewaySrv, signingKey, tokenStorePath, opSettings, nil),
		string(runtime.RuntimeGatewaySDK):   runner.NewGatewaySDKDriverWithSettings(gatewaySrv, signingKey, tokenStorePath, opSettings, nil),
	}, nil
}
