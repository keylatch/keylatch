package gateway

import (
	"net/http"
	"strings"

	"github.com/keylatch/keylatch/internal/masking"
)

// writeCapabilities are HTTP methods / capability names that represent mutations.
var writeCapabilities = map[string]bool{
	"POST": true, "PUT": true, "PATCH": true, "DELETE": true,
	// Capability name prefixes.
}

// writeCapabilityNames are capability name patterns that represent write operations.
var writeCapabilityPrefixes = []string{"send", "write", "delete", "post", "create", "update", "patch"}

// UntrustedWriteGate is middleware that blocks combinations of untrusted content
// sources with write/send/delete capabilities. A request header cannot lift
// the block: the caller sets its own headers, so a header-borne approval
// would let an agent approve its own write.
type UntrustedWriteGate struct {
	policy     masking.UntrustedContentPolicy
	providerID string
}

// NewUntrustedWriteGate creates the middleware.
func NewUntrustedWriteGate(providerID string, policy masking.UntrustedContentPolicy) *UntrustedWriteGate {
	return &UntrustedWriteGate{
		policy:     policy,
		providerID: providerID,
	}
}

// Middleware returns an http.Handler that enforces the write gate.
func (g *UntrustedWriteGate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.policy.RequireApprovalOnWriteCombination {
			next.ServeHTTP(w, r)
			return
		}

		// Only gate when the provider is an untrusted-content source.
		if !masking.UntrustedContentProviders[g.providerID] {
			next.ServeHTTP(w, r)
			return
		}

		// Only gate write/mutation requests.
		if !isWriteRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		writeAuthBlockedError(w, "untrusted_write_requires_approval",
			"combining untrusted content source with write capability requires human approval, which the gateway cannot accept from a request")
	})
}

// isWriteRequest returns true if the request method is a mutation method.
func isWriteRequest(r *http.Request) bool {
	if writeCapabilities[r.Method] {
		return true
	}
	// Check capability from URL path heuristic.
	for _, prefix := range writeCapabilityPrefixes {
		if strings.Contains(strings.ToLower(r.URL.Path), prefix) {
			return true
		}
	}
	return false
}
