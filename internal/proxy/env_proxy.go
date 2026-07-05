package proxy

import "strings"

// keylatchProxyEnvVars are the env vars injected for gateway_proxy runtime.
var keylatchProxyEnvVars = []string{
	"KEYLATCH_GATEWAY_URL",
	"KEYLATCH_SESSION_TOKEN",
	"KEYLATCH_CA_CERT",
}

// EnvInject returns a new env slice with KEYLATCH_GATEWAY_URL, KEYLATCH_SESSION_TOKEN,
// and KEYLATCH_CA_CERT injected, replacing any existing values. It also injects
// SSL CA env vars pointing to caPath when caPath is non-empty.
//
// sessionToken (the proxy caller-auth check) is the proxy's own
// per-session bearer token (see Server.EnsureToken/Server.Token). The child
// process must present it back to the proxy listener as
// "Proxy-Authorization: Bearer <sessionToken>" on every request; requests
// without a valid token are rejected with 401. Callers (see
// internal/runner/driver_proxy.go) obtain this value via
// (*proxy.Server).EnsureToken() — it is NOT the gateway-token-store JWT
// minted for audit/revocation tracking, which is a separate concern.
//
// This ensures the child env contains ONLY the keylatch session env vars.
// Provider API keys MUST be absent — callers are responsible for ensuring the
// base env does not contain provider keys.
func EnvInject(baseEnv []string, proxyAddr, sessionToken, caPath string) []string {
	// Strip any existing keylatch proxy env vars and CA env vars from base.
	result := make([]string, 0, len(baseEnv)+len(keylatchProxyEnvVars)+len(caEnvVars)+1)
	for _, entry := range baseEnv {
		if isKeylatchProxyEntry(entry) || (caPath != "" && isCAEnvEntry(entry)) {
			continue
		}
		result = append(result, entry)
	}

	// Inject keylatch proxy vars.
	result = append(result, "KEYLATCH_GATEWAY_URL=http://"+proxyAddr)
	result = append(result, "KEYLATCH_SESSION_TOKEN="+sessionToken)
	if caPath != "" {
		result = append(result, "KEYLATCH_CA_CERT="+caPath)
		// Also inject standard CA bundle env vars so all HTTP clients trust the CA.
		result = InjectCAEnv(result, caPath, true)
	}

	result = append(result, "KEYLATCH_RUNTIME=gateway_proxy")
	return result
}

// isKeylatchProxyEntry returns true if entry is a keylatch proxy env var assignment.
func isKeylatchProxyEntry(entry string) bool {
	for _, name := range keylatchProxyEnvVars {
		if strings.HasPrefix(entry, name+"=") {
			return true
		}
	}
	return strings.HasPrefix(entry, "KEYLATCH_RUNTIME=")
}
