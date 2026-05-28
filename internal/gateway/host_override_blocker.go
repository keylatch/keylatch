package gateway

import (
	"net/http"
	"strings"
)

// blockedOverrideHeaders are headers that agents must not use to override routing.
var blockedOverrideHeaders = []string{
	"X-Forwarded-Host",
	"X-Original-URL",
	"X-Rewrite-URL",
}

// hostOverrideBlockerMiddleware blocks:
//   - X-Forwarded-Host, X-Original-URL, X-Rewrite-URL headers.
//   - Host header overrides to off-allowlist hosts.
//
// Returns 403 on violation.
func hostOverrideBlockerMiddleware(next http.Handler, allowedHosts []string) http.Handler {
	allowedSet := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		allowedSet[strings.ToLower(stripPort(h))] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block forbidden override headers.
		for _, hdr := range blockedOverrideHeaders {
			if r.Header.Get(hdr) != "" {
				writeAuthBlockedError(w, "host_override_header_blocked",
					hdr+" header is not permitted")
				return
			}
		}

		// Block Host header override to off-allowlist host (if allowedHosts non-empty).
		if len(allowedHosts) > 0 {
			host := r.Header.Get("Host")
			if host == "" {
				host = r.Host
			}
			hostOnly := strings.ToLower(stripPort(host))
			if hostOnly != "" && !allowedSet[hostOnly] {
				writeAuthBlockedError(w, "host_override_blocked",
					"Host header points to off-allowlist host")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// stripPort removes the port component from a host:port string.
func stripPort(hostport string) string {
	if idx := strings.LastIndex(hostport, ":"); idx >= 0 {
		// Only strip if what's before the colon looks like a hostname
		// (not an IPv6 address bracket like [::1]).
		if !strings.Contains(hostport[:idx], ":") {
			return hostport[:idx]
		}
	}
	return hostport
}
