// Package approval — policy.go implements the configurable approval policy.
//
// Three modes are supported:
//   - trust:     auto-approve every request immediately.
//   - first-run: approve the first request per (actor, capability, connection)
//     triple per session; auto-approve identical subsequent requests.
//   - prompt:    require explicit human approval for every request.
//
// The mode is read from the per-connection YAML config field `approval_mode`.
// When the field is absent the DefaultMode function selects an appropriate mode
// based on the runtime context.
package approval

import (
	"context"
	"fmt"
	"sync"
)

// ApprovalMode is the policy that governs when a request requires human approval.
type ApprovalMode string

const (
	// ModeTrust auto-approves every request. Suitable for gateway/brokered paths
	// where the transport itself provides isolation.
	ModeTrust ApprovalMode = "trust"

	// ModeFirstRun approves the first request per session for each unique
	// (actor, capability, connection) triple and auto-approves identical
	// subsequent requests. Balances security with usability.
	ModeFirstRun ApprovalMode = "first-run"

	// ModePrompt requires explicit human approval for every request.
	// Highest security — use on value-bearing paths or shared accounts.
	ModePrompt ApprovalMode = "prompt"
)

// RuntimeMode is the execution context that can influence the default policy.
type RuntimeMode string

const (
	// RuntimeGateway represents gateway/brokered execution paths.
	RuntimeGateway RuntimeMode = "gateway"

	// RuntimeDirect represents direct value-bearing execution paths.
	RuntimeDirect RuntimeMode = "direct"
)

// DefaultMode returns the recommended ApprovalMode for a given runtime context.
// Gateway and brokered paths default to trust because the transport already
// provides isolation. Direct value-bearing paths default to first-run so the
// operator reviews the first access and subsequent identical requests flow freely.
func DefaultMode(rt RuntimeMode) ApprovalMode {
	switch rt {
	case RuntimeGateway:
		return ModeTrust
	default:
		return ModeFirstRun
	}
}

// ParseApprovalMode converts a string to an ApprovalMode.
// Returns an error if the string does not match a known mode.
func ParseApprovalMode(s string) (ApprovalMode, error) {
	switch ApprovalMode(s) {
	case ModeTrust, ModeFirstRun, ModePrompt:
		return ApprovalMode(s), nil
	case "":
		return ModeFirstRun, nil // default when not set
	default:
		return "", fmt.Errorf("approval: unknown mode %q; must be one of: trust, first-run, prompt", s)
	}
}

// sessionKey identifies a unique (actor, capability, connection) triple.
type sessionKey struct {
	actor      string
	capability string
	connection string
}

// PolicyChecker evaluates whether a request needs human approval under
// the configured policy mode.
type PolicyChecker struct {
	mode ApprovalMode

	mu   sync.Mutex
	seen map[sessionKey]bool // used by first-run mode
}

// NewPolicyChecker creates a PolicyChecker for the given mode.
func NewPolicyChecker(mode ApprovalMode) *PolicyChecker {
	return &PolicyChecker{
		mode: mode,
		seen: make(map[sessionKey]bool),
	}
}

// PolicyDecision is the outcome of a policy check.
type PolicyDecision string

const (
	// DecisionApproved means the request is approved without human interaction.
	DecisionApproved PolicyDecision = "approved"

	// DecisionRequiresApproval means the request must be presented to a human.
	DecisionRequiresApproval PolicyDecision = "requires_approval"
)

// Check evaluates the policy for a request identified by (actor, capability, connection).
// For trust mode it always returns DecisionApproved.
// For first-run mode it approves the first unique triple per session and auto-approves
// identical subsequent requests.
// For prompt mode it always returns DecisionRequiresApproval.
func (p *PolicyChecker) Check(_ context.Context, actor, capability, connection string) PolicyDecision {
	switch p.mode {
	case ModeTrust:
		return DecisionApproved

	case ModeFirstRun:
		key := sessionKey{actor: actor, capability: capability, connection: connection}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.seen[key] {
			return DecisionApproved
		}
		// Mark as seen — the first occurrence requires approval, subsequent ones
		// flow through automatically. The caller is responsible for waiting for
		// human approval before marking the key as seen; here we mark it so that
		// the next Check call for the same triple returns DecisionApproved.
		p.seen[key] = true
		return DecisionRequiresApproval

	case ModePrompt:
		return DecisionRequiresApproval

	default:
		// Unknown mode — fail closed (require approval).
		return DecisionRequiresApproval
	}
}

// Mode returns the configured ApprovalMode.
func (p *PolicyChecker) Mode() ApprovalMode {
	return p.mode
}
