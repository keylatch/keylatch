package policy_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/policy"
)

// TestPermissiveGate_LLMSessionPanics verifies invariants:
// 1. permissive mode + LLM session panics (Check must panic)
// 2. unsetting CI does NOT bypass the panic
// 3. non-LLM sessions with permissive mode work fine
func TestPermissiveGate_LLMSessionPanics(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModePermissive,
		DefaultDeny:   false,
	}

	// Must panic with LLM session.
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		p.Check(policy.Request{LLMSession: true, Capability: "inject"})
	}()
	if !panicked {
		t.Error("permissive+LLM session must panic")
	}
}

// TestPermissiveGate_NoCI_StillPanics verifies that removing a CI env var
// does NOT bypass the permissive+LLM panic (no CI check in the policy engine).
func TestPermissiveGate_NoCI_StillPanics(t *testing.T) {
	// Ensure CI is unset for this test.
	// (The policy engine must NOT check CI — the panic is unconditional.)
	t.Setenv("CI", "")

	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModePermissive,
		DefaultDeny:   false,
	}

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		p.Check(policy.Request{LLMSession: true, Capability: "inject"})
	}()
	if !panicked {
		t.Error("permissive+LLM session must panic even with CI unset")
	}
}

// TestPermissiveGate_NonLLM_Works verifies permissive mode works fine for
// non-LLM sessions (no rules, default-allow).
func TestPermissiveGate_NonLLM_Works(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModePermissive,
		DefaultDeny:   false,
	}

	d := p.Check(policy.Request{
		LLMSession: false,
		Actor:      "human-shell",
		Connection: "a:b",
		Capability: "inject",
	})
	if !d.Allow {
		t.Error("permissive mode with non-LLM session should allow")
	}
}

// TestPermissiveGate_Enforcing_DoesNotPanic verifies enforcing mode + LLM
// session does NOT panic (it just evaluates rules normally).
func TestPermissiveGate_Enforcing_DoesNotPanic(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true,
	}

	// Should not panic — enforcing mode is fine with LLM sessions.
	d := p.Check(policy.Request{
		LLMSession: true,
		Actor:      "claude-code",
		Connection: "a:b",
		Capability: "inject", // non-read-class
	})
	// Default deny with no rules.
	if d.Allow {
		t.Error("expected deny: enforcing, default_deny=true, no rules")
	}
}
