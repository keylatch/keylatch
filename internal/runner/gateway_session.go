package runner

import (
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// GatewayAddrPlaceholder stands in for the gateway host:port in a
// SessionEnv until the process that starts the child knows where the gateway
// is reachable from inside its own sandbox.
const GatewayAddrPlaceholder = "{gateway}"

// SessionEnv describes how a gateway-backed child environment differs from the
// caller's: variables to remove, and variables to set.
type SessionEnv struct {
	Strip []string    `json:"strip,omitempty"`
	Set   []EnvAssign `json:"set"`
}

// EnvAssign is one environment variable assignment.
type EnvAssign struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GatewaySessionEnv returns the child environment changes for a gateway_typed
// or gateway_sdk run. The provider key variables declared by the template are
// stripped; only the gateway URL or SDK base URL, the session token and the
// runtime name are set.
func GatewaySessionEnv(mode runtime.RuntimeMode, tmpl registry.ConnectionTemplate, gatewayURL, jwtStr string) SessionEnv {
	env := SessionEnv{}
	for _, rule := range tmpl.InjectionRules {
		env.Strip = append(env.Strip, rule.EnvVar)
	}
	if mode == runtime.RuntimeGatewaySDK {
		env.Set = append(env.Set, EnvAssign{sdkBaseURLVar(tmpl), gatewayURL})
	} else {
		env.Set = append(env.Set, EnvAssign{"KEYLATCH_GATEWAY_URL", gatewayURL})
	}
	return SessionEnv{
		Strip: env.Strip,
		Set: append(env.Set,
			EnvAssign{"KEYLATCH_GATEWAY_TOKEN", jwtStr},
			EnvAssign{"KEYLATCH_RUNTIME", string(mode)},
		),
	}
}

// Apply builds the child environment from base. KEYLATCH_* variables are
// dropped except the ones the session sets; with cleanEnv the base is reduced
// to a minimal set first and extra names survive it.
func (s SessionEnv) Apply(base []string, cleanEnv bool, extra []string) []string {
	strip := make(map[string]struct{}, len(s.Strip))
	for _, name := range s.Strip {
		strip[name] = struct{}{}
	}
	kept := make([]string, 0, len(base))
	for _, e := range base {
		name := e
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				name = e[:i]
				break
			}
		}
		if _, drop := strip[name]; !drop {
			kept = append(kept, e)
		}
	}

	var out []string
	if cleanEnv {
		out = runtime.CleanBaseEnv(kept, extra...)
	} else {
		keep := make([]string, 0, len(s.Set))
		for _, a := range s.Set {
			keep = append(keep, a.Name)
		}
		out = runtime.FilterChildEnv(kept, keep...)
	}
	for _, a := range s.Set {
		out = appendOrReplace(out, a.Name, a.Value)
	}
	return out
}
