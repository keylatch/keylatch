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

// approvalTokenHeader is the header name used to supply approval tokens.
const approvalTokenHeader = "X-Keylatch-Approval-Token" //nolint:gosec // G101 false positive: this is a header name, not a credential value

// UntrustedWriteGate is middleware that blocks combinations of untrusted content
// sources with write/send/delete capabilities unless approval is present.
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

		// Check for approval token.
		if r.Header.Get(approvalTokenHeader) != "" {
			next.ServeHTTP(w, r)
			return
		}

		// Block.
		writeAuthBlockedError(w, "untrusted_write_requires_approval",
			"combining untrusted content source with write capability requires approval token")
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
