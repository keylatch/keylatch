package policy_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/policy"
)

// TestActorSpoof_FIND007 verifies FIND-007:
// even if KEYLATCH_ACTOR is set to "human" (actor spoofing), the LLM session
// read-class deny (S8-9) is applied based on req.LLMSession, not the actor name.
func TestActorSpoof_FIND007_ReadDenied(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   false, // would allow if not for S8-9
		Rules: []policy.Rule{
			{
				ID:           "allow-all",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"read"},
			},
		},
	}

	// Simulate: KEYLATCH_ACTOR=human with LLMSession=true (actor spoofing).
	// The decision should still deny because LLMSession=true + read capability.
	d := p.Check(policy.Request{
		Actor:      "human", // actor says "human" — but it's spoofed
		Connection: "openrouter:dev",
		Capability: "read",
		LLMSession: true, // signal from llmcontext, cannot be spoofed by actor name
	})

	if d.Allow {
		t.Error("FIND-007: read capability must be denied in LLM session even with spoofed actor name")
	}
	if d.Reason == "" {
		t.Error("Reason must be set on LLM read deny")
	}
}

// TestActorSpoof_FIND007_ExportDenied confirms export is also denied.
func TestActorSpoof_FIND007_ExportDenied(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   false,
		Rules: []policy.Rule{
			{
				ID:           "allow-export",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"export"},
			},
		},
	}

	d := p.Check(policy.Request{
		Actor:      "human-shell",
		Connection: "a:b",
		Capability: "export",
		LLMSession: true,
	})

	if d.Allow {
		t.Error("FIND-007: export capability must be denied regardless of actor name in LLM session")
	}
}

// TestActorSpoof_FIND007_InjectAllowed confirms non-read capabilities still
// go through normal rule evaluation even with a spoofed actor name.
func TestActorSpoof_FIND007_InjectAllowed(t *testing.T) {
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   false,
		Rules: []policy.Rule{
			{
				ID:           "allow-inject",
				Actor:        "human-shell",
				Connections:  []string{"*"},
				Capabilities: []string{"inject"},
			},
		},
	}

	d := p.Check(policy.Request{
		Actor:      "human-shell",
		Connection: "a:b",
		Capability: "inject",
		LLMSession: true,
	})

	// inject is not a read-class capability — should be allowed.
	if !d.Allow {
		t.Error("inject capability in LLM session (non-read-class) should be allowed by matching rule")
	}
}
