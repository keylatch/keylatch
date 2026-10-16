package runner_test

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
)

func TestPolicyDeniedErrorMatchesSentinels(t *testing.T) {
	deny := &runner.PolicyDeniedError{Decision: enforce.Decision{Reason: "no policy for openai: run `keylatch policy init`"}}
	if !errors.Is(deny, runner.ErrPolicyDeny) || errors.Is(deny, runner.ErrApprovalRequired) {
		t.Fatalf("deny matches the wrong sentinel: %v", deny)
	}
	assert.Contains(t, deny.Error(), "no policy for openai")

	approval := &runner.PolicyDeniedError{Decision: enforce.Decision{Allow: true, ApprovalRequired: true}}
	if !errors.Is(approval, runner.ErrApprovalRequired) || errors.Is(approval, runner.ErrPolicyDeny) {
		t.Fatalf("approval matches the wrong sentinel: %v", approval)
	}
}
