// Package ui provides the HTTP server and handler infrastructure for the
// keylatch local browser UI.
package ui

import "errors"

// UISessionScope defines what operations the UI session is permitted to perform.
// Scope is determined at server startup from CLI flags and LLM session detection.
type UISessionScope int

const (
	// ScopeStatusOnly: read-only status queries only. Assigned automatically
	// when CLAUDE_CODE=1 (or any LLM session signal) is set.
	ScopeStatusOnly UISessionScope = iota

	// ScopeSetup: first-run wizard; allows creating connections but not
	// minting tokens or managing existing credentials.
	ScopeSetup

	// ScopeAdmin: full read/write access to connections, approvals, and settings.
	// Default scope when no LLM session is detected.
	ScopeAdmin

	// ScopeTokenMinting: superset of Admin; additionally allows POST /api/gateway/tokens.
	// Must be explicitly requested via --scope=token-minting CLI flag.
	ScopeTokenMinting
)

// ErrScopeInsufficient is returned when an operation requires a higher scope.
var ErrScopeInsufficient = errors.New("ui: operation not permitted for current session scope")

// DefaultScope returns the appropriate default scope given the LLM session state.
// When isLLM is true, scope is restricted to ScopeStatusOnly regardless of other flags.
func DefaultScope(isLLM bool) UISessionScope {
	if isLLM {
		return ScopeStatusOnly
	}
	return ScopeAdmin
}

// ScopeFilter returns true if the given scope is sufficient for the required minimum scope.
func ScopeFilter(have, need UISessionScope) bool {
	return have >= need
}

// String returns a human-readable scope label.
func (s UISessionScope) String() string {
	switch s {
	case ScopeStatusOnly:
		return "status-only"
	case ScopeSetup:
		return "setup"
	case ScopeAdmin:
		return "admin"
	case ScopeTokenMinting:
		return "token-minting"
	default:
		return "unknown"
	}
}

// ParseScope parses a scope string from CLI flags.
func ParseScope(s string) (UISessionScope, error) {
	switch s {
	case "status-only":
		return ScopeStatusOnly, nil
	case "setup":
		return ScopeSetup, nil
	case "admin":
		return ScopeAdmin, nil
	case "token-minting":
		return ScopeTokenMinting, nil
	default:
		return ScopeStatusOnly, errors.New("ui: unknown scope: " + s)
	}
}
