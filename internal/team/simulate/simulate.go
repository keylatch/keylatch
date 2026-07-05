// Package simulate implements policy simulation (dry-run).
package simulate

import (
	"context"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/orgpolicy"
)

// SimResult is the result of a policy simulation.
type SimResult struct {
	Decision    string // "allow" | "deny" | "approval_required"
	Reason      string
	RuleID      string
	OrgOverride bool // true if org policy overrode local rule
	Risks       []Risk
}

// Risk describes a security risk associated with a simulation result.
type Risk struct {
	Level   string // "low" | "medium" | "high" | "critical"
	Message string
}

// Simulate runs policy.Check in dry-run mode against a capability+env+member.
// Returns SimResult without actually executing the operation.
func Simulate(ctx context.Context, capability, env string, member team.Member) (*SimResult, error) {
	result := &SimResult{
		Decision: "allow",
		Reason:   "no policy rules loaded in simulation (default-allow)",
	}

	// Check org policy first.
	bundle := orgpolicy.Active(ctx)
	if bundle != nil {
		local := orgpolicy.Decision{Allow: true, Reason: "local default-allow"}
		composed := orgpolicy.Compose(ctx, bundle, local, capability, env)
		if !composed.Allow {
			result.Decision = "deny"
			result.Reason = composed.Reason
			result.OrgOverride = true
			result.Risks = append(result.Risks, Risk{
				Level:   "high",
				Message: "Org policy baseline denies this capability",
			})
			return result, nil
		}
		if composed.ApprovalRequired {
			result.Decision = "approval_required"
			result.Reason = composed.Reason
			result.OrgOverride = true
		}
	}

	// Apply basic risk heuristics based on capability.
	result.Risks = assessRisks(capability, env, member)

	// Check if approval is required based on risk level.
	for _, r := range result.Risks {
		if r.Level == "high" || r.Level == "critical" {
			if result.Decision == "allow" {
				result.Decision = "approval_required"
				result.Reason = fmt.Sprintf("high-risk capability %q requires approval in env %q", capability, env)
			}
		}
	}

	return result, nil
}

// assessRisks returns risk assessments for a capability+env+member combination.
func assessRisks(capability, env string, member team.Member) []Risk {
	var risks []Risk

	// Write capabilities in production are high risk.
	if isWriteCapability(capability) && env == "production" {
		risks = append(risks, Risk{
			Level:   "high",
			Message: fmt.Sprintf("Write capability %q in production environment", capability),
		})
	}

	// Read capabilities in production are medium risk.
	if isReadCapability(capability) && env == "production" {
		risks = append(risks, Risk{
			Level:   "medium",
			Message: fmt.Sprintf("Read capability %q in production environment", capability),
		})
	}

	// Viewer trying to write is a red flag.
	if member.Role == team.RoleViewer && isWriteCapability(capability) {
		risks = append(risks, Risk{
			Level:   "critical",
			Message: "Viewer role attempting write operation",
		})
	}

	return risks
}

func isWriteCapability(cap string) bool {
	return cap == "write" || strings.HasSuffix(cap, ".write") || cap == "delete" || cap == "rotate"
}

func isReadCapability(cap string) bool {
	return cap == "read" || cap == "export" || strings.HasSuffix(cap, ".read") || strings.HasSuffix(cap, ".reveal")
}

// Explain returns a human-readable explanation of why a SimResult was reached.
func Explain(result *SimResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Decision: %s\n", result.Decision)
	fmt.Fprintf(&sb, "Reason: %s\n", result.Reason)
	if result.RuleID != "" {
		fmt.Fprintf(&sb, "Matched Rule: %s\n", result.RuleID)
	}
	if result.OrgOverride {
		sb.WriteString("Note: Org policy overrode local rule.\n")
	}
	if len(result.Risks) > 0 {
		sb.WriteString("Risks:\n")
		for _, r := range result.Risks {
			fmt.Fprintf(&sb, " [%s] %s\n", r.Level, r.Message)
		}
	}
	return sb.String()
}

// RiskReport generates a risk report for a set of capabilities against current policy.
func RiskReport(ctx context.Context, capabilities []string, member team.Member) ([]SimResult, error) {
	results := make([]SimResult, 0, len(capabilities))
	for _, cap := range capabilities {
		r, err := Simulate(ctx, cap, "", member)
		if err != nil {
			return nil, fmt.Errorf("simulate: risk report for %q: %w", cap, err)
		}
		r.RuleID = "simulated:" + cap
		results = append(results, *r)
	}
	return results, nil
}
