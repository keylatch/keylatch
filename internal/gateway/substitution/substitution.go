// Package substitution implements secret-substitution prevention.
// Enforced on every gateway request.
package substitution

import (
	"errors"
	"net/http"
	"strings"
)

// ErrSubstitutionBlocked is returned when a substitution attempt is detected.
var ErrSubstitutionBlocked = errors.New("substitution: blocked")

// known provider token endpoints that must never be proxied.
var tokenEndpoints = []string{
	"/oauth/token",
	"/login/oauth/access_token",
	"/oauth2/token",
	"/token",
	"/auth/token",
	"/connect/token",
}

// apiKeyParams are query parameter names that indicate credential injection.
var apiKeyParams = []string{
	"api_key",
	"apikey",
	"key",
	"token",
	"access_token",
	"secret",
}

// CheckRequest inspects an incoming gateway request and returns
// ErrSubstitutionBlocked if any substitution attack pattern is detected.
//
// Returns (kind string, error) where kind is one of:
//   - "auth_header" — Authorization header present (and not allowed)
//   - "api_key_param" — API-key-shaped query parameter present
//   - "token_endpoint" — Path matches a known provider token endpoint
//   - "host_override" — X-Forwarded-Host or Host override outside upstreamHost
func CheckRequest(r *http.Request, upstreamHost string, allowedParams map[string]bool, allowAgentAuth bool) (string, error) {
	if r == nil {
		return "", nil
	}

	// Check Authorization header (unless allowAgentAuth).
	if !allowAgentAuth {
		if r.Header.Get("Authorization") != "" {
			return "auth_header", ErrSubstitutionBlocked
		}
	}

	// Check for API-key-shaped query parameters.
	q := r.URL.Query()
	for _, param := range apiKeyParams {
		if v := q.Get(param); v != "" {
			if allowedParams != nil && allowedParams[param] {
				continue
			}
			return "api_key_param", ErrSubstitutionBlocked
		}
	}

	// Check path against known token endpoints.
	path := r.URL.Path
	for _, ep := range tokenEndpoints {
		if path == ep || strings.HasSuffix(path, ep) {
			return "token_endpoint", ErrSubstitutionBlocked
		}
	}

	// Check for host override (X-Forwarded-Host, Host header).
	if upstreamHost != "" {
		// X-Forwarded-Host override.
		if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
			if !hostMatches(fwdHost, upstreamHost) {
				return "host_override", ErrSubstitutionBlocked
			}
		}
		// Explicit Host header override (if different from upstream).
		if r.Host != "" && !hostMatches(r.Host, upstreamHost) {
			// Only block if the Host header explicitly differs from the gateway address.
			// We allow it when it matches the upstream host.
			if !isGatewayHost(r.Host) {
				return "host_override", ErrSubstitutionBlocked
			}
		}
	}

	return "", nil
}

// hostMatches checks whether candidate matches upstreamHost (ignoring port).
func hostMatches(candidate, upstreamHost string) bool {
	// Strip port from both.
	c := stripPort(candidate)
	u := stripPort(upstreamHost)
	return strings.EqualFold(c, u)
}

// stripPort removes the port suffix from a host string.
func stripPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		// Only strip if what follows looks like a port (all digits).
		port := host[idx+1:]
		allDigits := true
		for _, r := range port {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return host[:idx]
		}
	}
	return host
}

// isGatewayHost returns true if host is a loopback gateway address.
func isGatewayHost(host string) bool {
	h := stripPort(host)
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}
