package budget

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// budgetMiddlewareHMACKey is a per-process key for actor ID hashing in receipts.
// In production this would be the broker's hmacKey.
var budgetMiddlewareHMACKey = []byte("keylatch-budget-hmac-key-v1")

// BudgetMiddleware enforces per-actor budget limits on gateway requests.
type BudgetMiddleware struct {
	counter    BudgetCounter
	capability string
	amount     float64 // amount to check/record per request
}

// NewBudgetMiddleware creates the middleware for a given capability.
func NewBudgetMiddleware(counter BudgetCounter, capability string, amountPerRequest float64) *BudgetMiddleware {
	return &BudgetMiddleware{
		counter:    counter,
		capability: capability,
		amount:     amountPerRequest,
	}
}

// Handler wraps next with budget enforcement.
//
// WARNING: this HTTP-middleware form resolves the actor from the
// X-Keylatch-Actor header, which is client-controlled. It exists for tests
// and reference only — do NOT mount it on a production chain. The live
// gateway enforces budgets inline in gatewayHandler using the verified JWT
// actor claim.
// Uses CheckAndRecord atomically before dispatching to avoid TOCTOU (C-4).
// All attempts are counted; failed handlers do not decrement (pragmatic safe approach).
func (m *BudgetMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := actorFromRequest(r)

		// Atomic check-and-record: reserves the budget slot before the handler runs.
		// This prevents concurrent callers from both passing a shared check before either records.
		if err := m.counter.CheckAndRecord(r.Context(), actor, m.capability, m.amount); err != nil {
			receipt := BudgetDenialReceipt{
				ActorHMAC:  hashActorID(actor),
				Capability: m.capability,
				LimitType:  "request_budget",
				LimitValue: m.amount,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			b, _ := json.Marshal(receipt)
			_, _ = w.Write(b)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// actorFromRequest extracts the actor identity from the request.
// In production this comes from the verified JWT token claim.
func actorFromRequest(r *http.Request) string {
	// The gateway verifies the JWT and sets actor in a context value.
	// For budget middleware, we use the raw JWT sub as actor — it will be
	// HMAC'd before appearing in any output.
	return r.Header.Get("X-Keylatch-Actor")
}

// hashActorID returns an HMAC-SHA256 hex digest of actorID.
func hashActorID(actorID string) string {
	return HashActor(budgetMiddlewareHMACKey, actorID)
}

// DeriveActorHashKey derives a domain-separated sub-key from a signing key
// for actor hashing, so denial receipts are never HMAC'd under the raw JWT
// signing key (key-reuse hygiene).
func DeriveActorHashKey(signingKey []byte) []byte {
	h := hmac.New(sha256.New, signingKey)
	h.Write([]byte("keylatch-actor-hmac-v1"))
	return h.Sum(nil)
}

// HashActor returns a truncated HMAC-SHA256 hex digest of actor under key.
// Callers with a real signing key (e.g. the gateway) should pass a key from
// DeriveActorHashKey instead of the package-level fallback key so receipts
// are keyed per deployment and domain-separated from JWT signing.
func HashActor(key []byte, actor string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(actor))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// captureResponseWriter wraps http.ResponseWriter to capture the status code.
//
//nolint:unused // planned: used by budget audit middleware in Phase 9 response size accounting
type captureResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (crw *captureResponseWriter) WriteHeader(code int) { //nolint:unused // planned: used by captureResponseWriter
	crw.statusCode = code
	crw.ResponseWriter.WriteHeader(code)
}
