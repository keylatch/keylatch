package policy_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/policy"
)

// TestDecision_MatchedGrantID_TypeSafe verifies that MatchedGrantID is a string
// field and can be set and retrieved without type assertions.
func TestDecision_MatchedGrantID_TypeSafe(t *testing.T) {
	const grantID = "grant-abc-123"
	d := policy.Decision{
		Allow:          true,
		MatchedGrantID: grantID,
		Reason:         "grant:" + grantID,
	}

	if d.MatchedGrantID != grantID {
		t.Errorf("MatchedGrantID = %q, want %q", d.MatchedGrantID, grantID)
	}

	// Confirm it is a plain string — no type assertion needed.
	_ = d.MatchedGrantID
}
