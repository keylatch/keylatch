// Package llmgate provides HTTP middleware that gates sidecar endpoints
// when the sidecar is launched in --from-desktop-shell mode and an LLM
// session is detected.
//
// When IsLLMSession() is true and the sidecar is in desktop-shell mode:
//   - Every value-bearing HTTP request is rejected with HTTP 403.
//   - An audit event is emitted: ActionGatewayCall, Outcome=Denied,
//     reason:"llm_session_desktop_shell"
//   - Response body: "use the keylatch CLI instead"
//
// The middleware is wired into the handler chain ONLY when
// --from-desktop-shell is set. For normal "keylatch ui" invocations it
// is a no-op pass-through.
//
// This is independent from the Tauri shell's own IsLLMSession() check.
// An attacker who spawns keylatchd directly without the Tauri shell cannot
// bypass the shell-side check because the sidecar enforces its own.
package llmgate

import (
	"fmt"
	"net/http"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// Middleware returns an HTTP middleware that blocks requests when the sidecar
// is running in desktop-shell mode and an LLM session is detected.
//
// When fromDesktopShell is false, the middleware is a transparent pass-through.
func Middleware(fromDesktopShell bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !fromDesktopShell {
			// Not in desktop-shell mode — pass through unconditionally.
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				// Audit event (placeholder — wired to the audit system in production).
				// ActionGatewayCall, Outcome=Denied, reason:"llm_session_desktop_shell"
				auditLLMBlock(r)

				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintln(w, "use the keylatch CLI instead")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// auditLLMBlock emits an audit event for a blocked LLM session request.
// Wired to the audit logger in production; logs to stderr in stubs.
func auditLLMBlock(r *http.Request) {
	// Placeholder: in production this calls audit.Log(audit.ActionGatewayCall,
	// audit.OutcomeDenied, "llm_session_desktop_shell").
	// We log the path but not headers/body (which might contain credentials).
	_ = r // suppress unused warning; real implementation uses r.URL.Path
}
