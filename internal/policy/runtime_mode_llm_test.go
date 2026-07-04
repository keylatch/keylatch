package policy_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/policy"
)

// TestRuntimeModeLLM_S817 tests the full matrix:
// 4 actors × 4 capabilities × 5 runtimes with LLMSession=true.
//
// Expected outcomes (read-class always denied; inject varies by runtime):
// - read/export/_.reveal/_.dump: always denied regardless of runtime.
// - inject: depends on rule.LLMSessions[runtime] setting.
func TestRuntimeModeLLM_S817(t *testing.T) {
	actors := []string{
		"claude-code",
		"codex",
		"llm-session",
		"unknown-non-tty",
	}
	readClassCaps := []string{
		"read",
		"export",
		"db.credentials.reveal",
		"db.dump",
	}
	runtimes := []string{
		"gateway_typed",
		"gateway_sdk",
		"direct_brokered",
		"gateway_proxy",
	}

	// Policy: deny LLM in direct_classic_sandboxed (no key = approval_required),
	// deny gateway_sdk, allow others.
	ruleWithLLMSessions := policy.Rule{
		ID:           "llm-runtime-rule",
		Actor:        "*",
		Connections:  []string{"*"},
		Capabilities: []string{"inject"},
		LLMSessions: map[string]string{
			"gateway_sdk":     "deny",
			"gateway_typed":   "allow",
			"direct_brokered": "allow",
			"gateway_proxy":   "allow",
			// direct_classic_sandboxed absent → approval_required
		},
	}
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true,
		Rules:         []policy.Rule{ruleWithLLMSessions},
	}

	// --- Read-class capabilities: always denied for LLM sessions ---
	for _, actor := range actors {
		for _, cap := range readClassCaps {
			for _, rt := range runtimes {
				d := p.Check(policy.Request{
					Actor:      actor,
					Connection: "openrouter:dev",
					Capability: cap,
					LLMSession: true,
					Runtime:    rt,
				})
				if d.Allow {
					t.Errorf("actor=%s cap=%s runtime=%s: expected deny, got allow (reason=%q)",
						actor, cap, rt, d.Reason)
				}
				// Verify stable reason string.
				if d.Reason != "read-class capabilities are denied in LLM sessions" {
					t.Errorf("stable reason mismatch for cap=%s: got %q", cap, d.Reason)
				}
			}
		}
	}

	// --- inject capability: varies by runtime ---
	type expectation struct {
		runtime        string
		wantAllow      bool
		wantApproval   bool
		wantDenyReason string
	}
	injectExpectations := []expectation{
		{runtime: "gateway_typed", wantAllow: true, wantApproval: false},
		{runtime: "gateway_sdk", wantAllow: false, wantDenyReason: "runtime gateway_sdk denied by rule.LLMSessions"},
		{runtime: "direct_brokered", wantAllow: true, wantApproval: false},
		{runtime: "gateway_proxy", wantAllow: true, wantApproval: false},
		// direct_classic_sandboxed is planned for 0.2.0 — denied immediately in 0.1.0.
		{runtime: "direct_classic_sandboxed", wantAllow: false, wantDenyReason: "0.2.0"},
	}

	for _, actor := range actors {
		for _, exp := range injectExpectations {
			d := p.Check(policy.Request{
				Actor:      actor,
				Connection: "openrouter:dev",
				Capability: "inject",
				LLMSession: true,
				Runtime:    exp.runtime,
			})

			if d.Allow != exp.wantAllow {
				t.Errorf("actor=%s runtime=%s inject: Allow=%v, want %v (reason=%q)",
					actor, exp.runtime, d.Allow, exp.wantAllow, d.Reason)
			}
			if exp.wantApproval && !d.ApprovalRequired {
				t.Errorf("actor=%s runtime=%s: expected ApprovalRequired=true", actor, exp.runtime)
			}
			if exp.wantDenyReason != "" && !strings.Contains(d.Reason, exp.wantDenyReason) {
				t.Errorf("actor=%s runtime=%s deny reason mismatch: got %q, want substring %q",
					actor, exp.runtime, d.Reason, exp.wantDenyReason)
			}
		}
	}
}
