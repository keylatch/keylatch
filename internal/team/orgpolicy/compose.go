package orgpolicy

import (
	"context"
	"path/filepath"
	"strings"
)

// Decision represents the result of a policy evaluation.
type Decision struct {
	Allow            bool
	Reason           string
	ApprovalRequired bool
}

// Compose applies the org AllowedEnvelope as a hard upper bound.
//
// - Org-deny overrides local allow.
// - Org-allow + local-narrow = local narrowing wins.
// - When no bundle installed, returns the localDecision unchanged (single-user mode).
func Compose(ctx context.Context, bundle *OrgBundle, localDecision Decision, capability string, env string) Decision {
	if bundle == nil {
		// No org policy: single-user mode — pass-through.
		return localDecision
	}

	// BaselineDeny: always denied regardless of local rule.
	for _, pattern := range bundle.BaselineDeny {
		if matchGlob(pattern, capability) {
			return Decision{
				Allow:  false,
				Reason: "denied by org policy baseline: " + pattern,
			}
		}
	}

	// DenyCapabilities in AllowedEnvelope.
	for _, pattern := range bundle.AllowedEnvelope.DenyCapabilities {
		if matchGlob(pattern, capability) {
			return Decision{
				Allow:  false,
				Reason: "denied by org AllowedEnvelope.DenyCapabilities: " + pattern,
			}
		}
	}

	// Check AllowedEnvs (glob match).
	if len(bundle.AllowedEnvelope.AllowedEnvs) > 0 && env != "" {
		allowed := false
		for _, pattern := range bundle.AllowedEnvelope.AllowedEnvs {
			if matchGlob(pattern, env) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Decision{
				Allow:  false,
				Reason: "environment " + env + " not in org AllowedEnvelope.AllowedEnvs",
			}
		}
	}

	// Check RequireApproval: if org requires approval and local does not, add approval requirement.
	for _, pattern := range bundle.AllowedEnvelope.RequireApproval {
		if matchGlob(pattern, capability) {
			if !localDecision.ApprovalRequired {
				localDecision.ApprovalRequired = true
				localDecision.Reason = "approval required by org policy for capability: " + capability
			}
			break
		}
	}

	// Org-allow + local-deny = deny (local narrowing wins).
	// Org-allow + local-narrow = local narrowing wins.
	// If the org allows but local denies, respect local deny.
	return localDecision
}

// matchGlob matches a capability against a glob pattern using filepath.Match semantics.
// Also supports simple prefix-* matching (e.g. "read*" matches "read.secrets").
func matchGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	// Use filepath.Match for standard glob patterns.
	matched, err := filepath.Match(pattern, value)
	if err == nil && matched {
		return true
	}
	// Also try simple string prefix/suffix matching for common patterns like "*.reveal".
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
