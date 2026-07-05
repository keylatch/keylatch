// Package fallback implements the ordered fallback chain for Root of Trust resolution.
// It evaluates a list of RootSpec entries in order, applying skip rules, and returns
// the first RootOfTrust that satisfies an Operation's requirements.
//
// Security invariant hardware-only policy NEVER silently downgrades to
// passphrase. Chain.Resolve returns ErrChainExhausted when RequiredRootTypes contains
// hardware roots and only passphrase roots are available.
package fallback

import (
	"context"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/trust"
)

// OperationKind describes the type of trust operation being requested.
type OperationKind string

const (
	OperationWrap     OperationKind = "wrap"
	OperationUnwrap   OperationKind = "unwrap"
	OperationSign     OperationKind = "sign"
	OperationPresence OperationKind = "presence"
	OperationApproval OperationKind = "approval"
)

// Operation describes the requirements for a trust operation.
type Operation struct {
	// Kind is the type of operation.
	Kind OperationKind
	// Capability is the required trust.Capability string name (e.g. "wrap", "sign_challenge").
	Capability string
	// LLMSession is true when the request originates from an LLM-driven session.
	LLMSession bool
	// InteractiveAllowed is true when a human terminal is available.
	InteractiveAllowed bool
	// RequiredRootTypes restricts resolution to specific root types.
	// An empty slice means any type is acceptable.
	// if this is non-empty and contains only hardware types, passphrase
	// roots are never selected as a fallback.
	RequiredRootTypes []trust.RootType
	// RequireAllOfRootIDs lists root spec IDs that ALL must be satisfied (two-person mode).
	// Used by ResolveAll; empty means standard first-wins mode.
	RequireAllOfRootIDs []string
}

// SkipReason describes why a root was skipped during chain resolution.
type SkipReason string

const (
	SkipNotActive       SkipReason = "not_active"
	SkipCapability      SkipReason = "capability_mismatch"
	SkipRootType        SkipReason = "root_type_not_required"
	SkipLLMPresence     SkipReason = "llm_session_presence_required"
	SkipLaunchdUnsafe   SkipReason = "not_launchd_safe"
	SkipConstructFailed SkipReason = "construct_failed"
)

// SkippedRoot records why a particular root was not selected.
type SkippedRoot struct {
	SpecID string
	Type   trust.RootType
	Reason SkipReason
	Detail string
}

// Reason collects the resolution outcome for Chain.Resolve.
type Reason struct {
	Skipped []SkippedRoot
	// ExhaustReason is a human-readable summary of why no root was found.
	ExhaustReason string
}

// Chain holds an ordered list of RootSpecs and resolves trust operations against them.
type Chain struct {
	specs []trust.RootSpec
}

// NewChain constructs a Chain from an ordered list of RootSpec entries.
func NewChain(specs []trust.RootSpec) *Chain {
	return &Chain{specs: specs}
}

// Resolve selects the first eligible RootOfTrust for op from the chain.
//
// Resolution algorithm:
// 1. Skip roots where Status != RootActive.
// 2. Skip roots where the required capability is not supported.
// 3. Skip roots not in op.RequiredRootTypes (if non-empty). hardware-only
// policies never silently downgrade to passphrase.
// 4. Skip presence-requiring roots in LLM sessions.
// 5. Skip non-launchd-safe roots when !op.InteractiveAllowed.
// 6. Try trust.New(spec) — first success wins.
//
// Returns ErrChainExhausted with full Reason if no root is eligible.
func (c *Chain) Resolve(ctx context.Context, op Operation) (trust.RootOfTrust, Reason, error) {
	capFlag := capabilityFromName(op.Capability)
	var skipped []SkippedRoot

	for _, spec := range c.specs {
		// Rule 1: status.
		if spec.Status != trust.RootActive {
			skipped = append(skipped, SkippedRoot{
				SpecID: spec.ID, Type: spec.Type, Reason: SkipNotActive,
			})
			continue
		}

		// Rule 2: capability check requires constructing a prototype.
		// We check capability by type using a lightweight table rather than constructing.
		if capFlag != 0 && !typeHasCapability(spec.Type, capFlag) {
			skipped = append(skipped, SkippedRoot{
				SpecID: spec.ID, Type: spec.Type, Reason: SkipCapability,
				Detail: op.Capability,
			})
			continue
		}

		// Rule 3: RequiredRootTypes filter.
		if len(op.RequiredRootTypes) > 0 && !rootTypeIn(spec.Type, op.RequiredRootTypes) {
			skipped = append(skipped, SkippedRoot{
				SpecID: spec.ID, Type: spec.Type, Reason: SkipRootType,
				Detail: fmt.Sprintf("not in %v", op.RequiredRootTypes),
			})
			continue
		}

		// Rule 4: LLM session + presence-requiring types.
		if op.LLMSession && requiresPresence(spec.Type) {
			skipped = append(skipped, SkippedRoot{
				SpecID: spec.ID, Type: spec.Type, Reason: SkipLLMPresence,
			})
			continue
		}

		// Rule 5: non-interactive (launchd) — pre-screen known non-safe types.
		// Post-construction check via Has(CapLaunchdSafe) is done in rule 6b.
		if !op.InteractiveAllowed && knownNonLaunchdSafe(spec.Type) {
			skipped = append(skipped, SkippedRoot{
				SpecID: spec.ID, Type: spec.Type, Reason: SkipLaunchdUnsafe,
			})
			continue
		}

		// Rule 6: try to construct.
		root, err := trust.New(spec)
		if err != nil {
			skipped = append(skipped, SkippedRoot{
				SpecID: spec.ID, Type: spec.Type, Reason: SkipConstructFailed,
				Detail: err.Error(),
			})
			continue
		}

		// Rule 6b: post-construction launchd-safe check via Has(CapLaunchdSafe).
		if !op.InteractiveAllowed && !root.Has(trust.CapLaunchdSafe) {
			_ = root.Close() // best-effort cleanup in skip path
			skipped = append(skipped, SkippedRoot{
				SpecID: spec.ID, Type: spec.Type, Reason: SkipLaunchdUnsafe,
			})
			continue
		}

		return root, Reason{Skipped: skipped}, nil
	}

	reason := Reason{
		Skipped:       skipped,
		ExhaustReason: buildExhaustReason(op, skipped),
	}
	return nil, reason, trust.ErrChainExhausted
}

// ResolveAll selects all roots identified by op.RequireAllOfRootIDs.
// All-or-nothing: if any required ID has no eligible root, returns ErrChainExhausted
// with the missing ID named in the error.
func (c *Chain) ResolveAll(ctx context.Context, op Operation) ([]trust.RootOfTrust, Reason, error) {
	if len(op.RequireAllOfRootIDs) == 0 {
		root, reason, err := c.Resolve(ctx, op)
		if err != nil {
			return nil, reason, err
		}
		return []trust.RootOfTrust{root}, reason, nil
	}

	var roots []trust.RootOfTrust
	var skipped []SkippedRoot

	capFlag := capabilityFromName(op.Capability)

	for _, reqID := range op.RequireAllOfRootIDs {
		found := false
		for _, spec := range c.specs {
			if spec.ID != reqID && string(spec.Type) != reqID {
				continue
			}
			if spec.Status != trust.RootActive {
				skipped = append(skipped, SkippedRoot{
					SpecID: spec.ID, Type: spec.Type, Reason: SkipNotActive,
				})
				continue
			}
			// Rule 2: capability check (mirrors Resolve).
			if capFlag != 0 && !typeHasCapability(spec.Type, capFlag) {
				skipped = append(skipped, SkippedRoot{
					SpecID: spec.ID, Type: spec.Type, Reason: SkipCapability,
					Detail: op.Capability,
				})
				continue
			}
			// Rule 3: RequiredRootTypes filter (mirrors Resolve).
			if len(op.RequiredRootTypes) > 0 && !rootTypeIn(spec.Type, op.RequiredRootTypes) {
				skipped = append(skipped, SkippedRoot{
					SpecID: spec.ID, Type: spec.Type, Reason: SkipRootType,
					Detail: "root-type-not-allowed-by-policy",
				})
				continue
			}
			if op.LLMSession && requiresPresence(spec.Type) {
				skipped = append(skipped, SkippedRoot{
					SpecID: spec.ID, Type: spec.Type, Reason: SkipLLMPresence,
				})
				continue
			}
			root, err := trust.New(spec)
			if err != nil {
				skipped = append(skipped, SkippedRoot{
					SpecID: spec.ID, Type: spec.Type, Reason: SkipConstructFailed,
					Detail: err.Error(),
				})
				continue
			}
			roots = append(roots, root)
			found = true
			break
		}

		if !found {
			reason := Reason{
				Skipped:       skipped,
				ExhaustReason: fmt.Sprintf("required root %q not available", reqID),
			}
			// Close any already-opened roots.
			for _, r := range roots {
				_ = r.Close() // best-effort cleanup before returning error
			}
			return nil, reason, fmt.Errorf("%w: required root %q missing", trust.ErrChainExhausted, reqID)
		}
	}

	return roots, Reason{Skipped: skipped}, nil
}

// --- capability tables ---

// typeHasCapability returns a fast static answer for whether a RootType typically
// supports a given Capability. Used to skip construction for obviously unsupported roots.
// Conservative: if uncertain, returns true (allow construction to decide).
func typeHasCapability(t trust.RootType, c trust.Capability) bool {
	switch c {
	case trust.CapWrap:
		// SSH agent Ed25519 only; others generally support wrap.
		return true // conservative: let construction decide
	case trust.CapSignChallenge:
		switch t {
		case trust.RootPassphrase, trust.RootEncryptedFile, trust.RootBitwarden, trust.RootOnePassword:
			return false
		}
		return true
	case trust.CapUserPresence:
		switch t {
		case trust.RootSecureEnclave, trust.RootFIDO2, trust.RootGPGCard:
			return true
		case trust.RootSSHAgent:
			return false // conservative; touch-required detection is runtime
		}
		return false
	case trust.CapHardwareBound:
		switch t {
		case trust.RootSecureEnclave, trust.RootFIDO2, trust.RootPKCS11:
			return true
		}
		return false
	}
	return true // unknown capability — allow construction to decide
}

// requiresPresence returns true for root types that always require physical user interaction.
func requiresPresence(t trust.RootType) bool {
	switch t {
	case trust.RootSecureEnclave, trust.RootFIDO2, trust.RootGPGCard:
		return true
	}
	return false
}

// knownNonLaunchdSafe returns true for root types that are KNOWN to require user interaction.
// Unknown types are not pre-screened here; the post-construction Has(CapLaunchdSafe) check handles them.
func knownNonLaunchdSafe(t trust.RootType) bool {
	switch t {
	case trust.RootSecureEnclave, trust.RootFIDO2, trust.RootGPGCard:
		return true
	}
	return false
}

// rootTypeIn returns true if t is in types.
func rootTypeIn(t trust.RootType, types []trust.RootType) bool {
	for _, rt := range types {
		if rt == t {
			return true
		}
	}
	return false
}

// capabilityFromName maps a string capability name to a Capability flag.
func capabilityFromName(name string) trust.Capability {
	switch strings.ToLower(name) {
	case "wrap":
		return trust.CapWrap
	case "sign_challenge", "sign":
		return trust.CapSignChallenge
	case "user_presence":
		return trust.CapUserPresence
	case "hardware_bound":
		return trust.CapHardwareBound
	case "launchd_safe":
		return trust.CapLaunchdSafe
	case "attestation":
		return trust.CapAttestation
	case "mtls_client_auth":
		return trust.CapMTLSClientAuth
	}
	return 0
}

func buildExhaustReason(op Operation, skipped []SkippedRoot) string {
	if len(skipped) == 0 {
		return "no roots configured"
	}
	reasons := make([]string, 0, len(skipped))
	for _, s := range skipped {
		reasons = append(reasons, fmt.Sprintf("%s(%s)", s.SpecID, s.Reason))
	}
	return fmt.Sprintf("all %d root(s) skipped: %s", len(skipped), strings.Join(reasons, ", "))
}
