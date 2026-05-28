package approval

import (
	"context"
	"testing"
)

// TestTrustMode_NeverBlocks verifies that trust mode always returns DecisionApproved.
func TestTrustMode_NeverBlocks(t *testing.T) {
	t.Parallel()
	checker := NewPolicyChecker(ModeTrust)

	for i := 0; i < 10; i++ {
		d := checker.Check(context.Background(), "actor-1", "inject", "openrouter")
		if d != DecisionApproved {
			t.Errorf("trust mode must always approve; got %q on iteration %d", d, i)
		}
	}
}

// TestFirstRunMode_ApprovesTwice verifies that first-run mode requires approval for the
// first call and auto-approves identical subsequent calls.
func TestFirstRunMode_ApprovesTwice(t *testing.T) {
	t.Parallel()
	checker := NewPolicyChecker(ModeFirstRun)

	// First call: requires approval.
	d1 := checker.Check(context.Background(), "actor-1", "inject", "openrouter")
	if d1 != DecisionRequiresApproval {
		t.Errorf("first-run first call must require approval; got %q", d1)
	}

	// Second call with same triple: auto-approved.
	d2 := checker.Check(context.Background(), "actor-1", "inject", "openrouter")
	if d2 != DecisionApproved {
		t.Errorf("first-run second call (same triple) must be approved; got %q", d2)
	}

	// Different triple: requires approval again.
	d3 := checker.Check(context.Background(), "actor-1", "inject", "anthropic")
	if d3 != DecisionRequiresApproval {
		t.Errorf("first-run different connection must require approval; got %q", d3)
	}
}

// TestFirstRunMode_DifferentActors verifies each actor has its own session state.
func TestFirstRunMode_DifferentActors(t *testing.T) {
	t.Parallel()
	checker := NewPolicyChecker(ModeFirstRun)

	// Actor A first call.
	d1 := checker.Check(context.Background(), "actor-A", "inject", "openrouter")
	if d1 != DecisionRequiresApproval {
		t.Errorf("actor-A first call must require approval; got %q", d1)
	}

	// Actor B first call (different actor, same capability + connection).
	d2 := checker.Check(context.Background(), "actor-B", "inject", "openrouter")
	if d2 != DecisionRequiresApproval {
		t.Errorf("actor-B first call must require approval (independent session); got %q", d2)
	}
}

// TestPromptMode_BlocksEveryTime verifies prompt mode always requires approval.
func TestPromptMode_BlocksEveryTime(t *testing.T) {
	t.Parallel()
	checker := NewPolicyChecker(ModePrompt)

	for i := 0; i < 5; i++ {
		d := checker.Check(context.Background(), "actor-1", "inject", "openrouter")
		if d != DecisionRequiresApproval {
			t.Errorf("prompt mode must always require approval; got %q on iteration %d", d, i)
		}
	}
}

// TestDefaultMode_GatewayIsTrust verifies that gateway runtime maps to trust mode.
func TestDefaultMode_GatewayIsTrust(t *testing.T) {
	t.Parallel()
	mode := DefaultMode(RuntimeGateway)
	if mode != ModeTrust {
		t.Errorf("DefaultMode(RuntimeGateway) = %q; want %q", mode, ModeTrust)
	}
}

// TestDefaultMode_DirectIsFirstRun verifies that direct runtime maps to first-run mode.
func TestDefaultMode_DirectIsFirstRun(t *testing.T) {
	t.Parallel()
	mode := DefaultMode(RuntimeDirect)
	if mode != ModeFirstRun {
		t.Errorf("DefaultMode(RuntimeDirect) = %q; want %q", mode, ModeFirstRun)
	}
}

// TestParseApprovalMode verifies valid and invalid mode strings.
func TestParseApprovalMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input   string
		want    ApprovalMode
		wantErr bool
	}{
		{"trust", ModeTrust, false},
		{"first-run", ModeFirstRun, false},
		{"prompt", ModePrompt, false},
		{"", ModeFirstRun, false}, // empty string defaults to first-run
		{"unknown", "", true},     // unknown mode errors
		{"TRUST", "", true},       // case-sensitive
	}
	for _, tt := range tests {
		got, err := ParseApprovalMode(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseApprovalMode(%q): err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseApprovalMode(%q) = %q; want %q", tt.input, got, tt.want)
		}
	}
}

// TestPolicyChecker_Mode verifies that Mode() returns the configured mode.
func TestPolicyChecker_Mode(t *testing.T) {
	t.Parallel()
	for _, m := range []ApprovalMode{ModeTrust, ModeFirstRun, ModePrompt} {
		checker := NewPolicyChecker(m)
		if checker.Mode() != m {
			t.Errorf("Mode() = %q; want %q", checker.Mode(), m)
		}
	}
}

// TestPolicyChecker_UnknownMode_FailsClosed verifies that an unknown mode returns
// DecisionRequiresApproval (fail-closed behavior).
func TestPolicyChecker_UnknownMode_FailsClosed(t *testing.T) {
	t.Parallel()
	checker := NewPolicyChecker(ApprovalMode("invalid-mode"))
	d := checker.Check(context.Background(), "actor", "cap", "conn")
	if d != DecisionRequiresApproval {
		t.Errorf("unknown mode must fail closed (require approval); got %q", d)
	}
}
