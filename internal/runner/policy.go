// Package runner extensions for policy gating.
package runner

import (
	"errors"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/policy/enforce"
)

// ErrPolicyDeny is returned when policy denies the request.
var ErrPolicyDeny = errors.New("policy: request denied")

// ErrApprovalRequired is returned when the policy decision requires approval.
var ErrApprovalRequired = errors.New("policy: approval required")

// PolicyDeniedError carries the decision that denied a request. It matches
// ErrPolicyDeny, or ErrApprovalRequired when the decision allowed the request
// pending an approval that cannot be collected here.
type PolicyDeniedError struct {
	Decision enforce.Decision
}

func (e *PolicyDeniedError) Error() string {
	reason := e.Decision.Reason
	if reason == "" {
		reason = "no rule allows the request"
	}
	if e.Decision.ApprovalRequired {
		return fmt.Sprintf("%v: %s", ErrApprovalRequired, reason)
	}
	return fmt.Sprintf("%v: %s", ErrPolicyDeny, reason)
}

// Is makes errors.Is(err, ErrPolicyDeny) and ErrApprovalRequired work.
func (e *PolicyDeniedError) Is(target error) bool {
	if e.Decision.ApprovalRequired {
		return target == ErrApprovalRequired
	}
	return target == ErrPolicyDeny
}

// Receipt describes the outcome of a policy-gated run call.
// All hash fields are value-free.
type Receipt struct {
	Actor          string        `json:"actor"`
	Connection     string        `json:"connection"`
	Capability     string        `json:"capability"`
	Runtime        string        `json:"runtime"`
	CommandHash    string        `json:"command_hash"`
	CWDHash        string        `json:"cwd_hash"`
	PolicyDecision string        `json:"policy_decision"`
	AuditAccessor  string        `json:"audit_accessor"`
	ExitCode       int           `json:"exit_code,omitempty"`
	Duration       time.Duration `json:"duration"`
	Timestamp      time.Time     `json:"timestamp"`
}
