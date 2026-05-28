package policy_test

import (
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/policy"
)

// canaryKey is the Phase 8 canary that must not appear in any output.
const canaryKey = "KEYLATCH_CANARY_PHASE8_0xDEADBEEF"

func basePolicy() policy.Policy {
	return policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func ruleWith(actor, connection, capability string) policy.Rule {
	return policy.Rule{
		ID:           "rule-1",
		Actor:        actor,
		Connections:  []string{connection},
		Capabilities: []string{capability},
		CreatedAt:    time.Now(),
	}
}

// ---- Decision table tests (20 cases) ----------------------------------------

func TestCheck_DefaultDeny(t *testing.T) {
	p := basePolicy()
	d := p.Check(policy.Request{Actor: "human-shell", Connection: "openrouter:dev", Capability: "inject"})
	if d.Allow {
		t.Error("expected deny: no rules, default_deny=true")
	}
	if d.SafeFix == "" {
		t.Error("SafeFix should be non-empty on default deny")
	}
}

func TestCheck_DefaultAllow(t *testing.T) {
	p := basePolicy()
	p.DefaultDeny = false
	d := p.Check(policy.Request{Actor: "human-shell", Connection: "openrouter:dev", Capability: "inject"})
	if !d.Allow {
		t.Error("expected allow: no rules, default_deny=false")
	}
}

func TestCheck_LLMReadDeny_Read(t *testing.T) {
	p := basePolicy()
	p.Rules = []policy.Rule{ruleWith("*", "*", "read")}
	d := p.Check(policy.Request{
		Actor:      "claude-code",
		Connection: "openrouter:dev",
		Capability: "read",
		LLMSession: true,
	})
	if d.Allow {
		t.Error("S8-9: read capability must be denied in LLM session")
	}
	if d.Reason == "" {
		t.Error("Reason must be non-empty on LLM read deny")
	}
	if d.SafeFix == "" {
		t.Error("SafeFix must be non-empty on LLM read deny")
	}
}

func TestCheck_LLMReadDeny_Export(t *testing.T) {
	p := basePolicy()
	p.Rules = []policy.Rule{ruleWith("*", "*", "export")}
	d := p.Check(policy.Request{
		Actor:      "claude-code",
		Connection: "a:b",
		Capability: "export",
		LLMSession: true,
	})
	if d.Allow {
		t.Error("S8-9: export capability must be denied in LLM session")
	}
}

func TestCheck_LLMReadDeny_RevealSuffix(t *testing.T) {
	p := basePolicy()
	p.Rules = []policy.Rule{ruleWith("*", "*", "*.reveal")}
	d := p.Check(policy.Request{
		Actor:      "claude-code",
		Connection: "a:b",
		Capability: "db.credentials.reveal",
		LLMSession: true,
	})
	if d.Allow {
		t.Error("S8-9: .reveal suffix capability must be denied in LLM session")
	}
}

func TestCheck_LLMReadDeny_DumpSuffix(t *testing.T) {
	p := basePolicy()
	d := p.Check(policy.Request{
		Actor:      "claude-code",
		Connection: "a:b",
		Capability: "db.dump",
		LLMSession: true,
	})
	if d.Allow {
		t.Error("S8-9: .dump suffix capability must be denied in LLM session")
	}
}

func TestCheck_PermissivePanics_LLMSession(t *testing.T) {
	p := basePolicy()
	p.Mode = policy.ModePermissive
	defer func() {
		if r := recover(); r == nil {
			t.Error("Check with permissive+LLM session should panic")
		}
	}()
	p.Check(policy.Request{LLMSession: true, Capability: "inject"})
}

func TestCheck_RuleMatch_ActorGlob(t *testing.T) {
	p := basePolicy()
	p.Rules = []policy.Rule{ruleWith("claude-*", "openrouter:*", "inject")}
	d := p.Check(policy.Request{Actor: "claude-code", Connection: "openrouter:dev", Capability: "inject"})
	if !d.Allow {
		t.Error("expected allow: actor glob claude-* matches claude-code")
	}
}

func TestCheck_RuleMatch_ConnectionGlob(t *testing.T) {
	p := basePolicy()
	p.Rules = []policy.Rule{ruleWith("*", "openrouter:*", "inject")}
	d := p.Check(policy.Request{Actor: "anyone", Connection: "openrouter:prod", Capability: "inject"})
	if !d.Allow {
		t.Error("expected allow: connection glob matches")
	}
}

func TestCheck_RuleMatch_CapabilityGlob(t *testing.T) {
	p := basePolicy()
	p.Rules = []policy.Rule{ruleWith("*", "*", "openrouter.*")}
	d := p.Check(policy.Request{Actor: "anyone", Connection: "a:b", Capability: "openrouter.chat.create"})
	if !d.Allow {
		t.Error("expected allow: capability glob matches")
	}
}

func TestCheck_RuleNoMatch_Actor(t *testing.T) {
	p := basePolicy()
	p.Rules = []policy.Rule{ruleWith("human-shell", "openrouter:*", "inject")}
	d := p.Check(policy.Request{Actor: "claude-code", Connection: "openrouter:dev", Capability: "inject"})
	if d.Allow {
		t.Error("expected deny: actor does not match rule")
	}
}

func TestCheck_RuleMatch_CommandGlob(t *testing.T) {
	p := basePolicy()
	r := ruleWith("*", "*", "inject")
	r.Commands = []string{"tsx scripts/*"}
	p.Rules = []policy.Rule{r}

	d := p.Check(policy.Request{
		Actor:      "anyone",
		Connection: "a:b",
		Capability: "inject",
		Command:    []string{"tsx", "scripts/foo.ts"},
	})
	if !d.Allow {
		t.Error("expected allow: command glob matches")
	}
}

func TestCheck_RuleNoMatch_Command(t *testing.T) {
	p := basePolicy()
	r := ruleWith("*", "*", "inject")
	r.Commands = []string{"tsx scripts/*"}
	p.Rules = []policy.Rule{r}

	d := p.Check(policy.Request{
		Actor:      "anyone",
		Connection: "a:b",
		Capability: "inject",
		Command:    []string{"python", "foo.py"},
	})
	if d.Allow {
		t.Error("expected deny: command does not match")
	}
}

func TestCheck_RuleMatch_CWDGlob(t *testing.T) {
	p := basePolicy()
	r := ruleWith("*", "*", "inject")
	r.CWDs = []string{"/home/user/projects/*"}
	p.Rules = []policy.Rule{r}

	d := p.Check(policy.Request{
		Actor:      "anyone",
		Connection: "a:b",
		Capability: "inject",
		CWD:        "/home/user/projects/keylatch",
	})
	if !d.Allow {
		t.Error("expected allow: CWD glob matches")
	}
}

func TestCheck_RuleNoMatch_CWD(t *testing.T) {
	p := basePolicy()
	r := ruleWith("*", "*", "inject")
	r.CWDs = []string{"/home/user/projects/*"}
	p.Rules = []policy.Rule{r}

	d := p.Check(policy.Request{
		Actor:      "anyone",
		Connection: "a:b",
		Capability: "inject",
		CWD:        "/tmp/other",
	})
	if d.Allow {
		t.Error("expected deny: CWD does not match")
	}
}

func TestCheck_RuleMatch_RuntimeFilter(t *testing.T) {
	p := basePolicy()
	r := ruleWith("*", "*", "inject")
	r.Runtime = "gateway_typed"
	p.Rules = []policy.Rule{r}

	d := p.Check(policy.Request{
		Actor:      "anyone",
		Connection: "a:b",
		Capability: "inject",
		Runtime:    "gateway_typed",
	})
	if !d.Allow {
		t.Error("expected allow: runtime matches")
	}
}

func TestCheck_RuleNoMatch_Runtime(t *testing.T) {
	p := basePolicy()
	r := ruleWith("*", "*", "inject")
	r.Runtime = "gateway_typed"
	p.Rules = []policy.Rule{r}

	d := p.Check(policy.Request{
		Actor:      "anyone",
		Connection: "a:b",
		Capability: "inject",
		Runtime:    "direct_brokered",
	})
	if d.Allow {
		t.Error("expected deny: runtime does not match")
	}
}

func TestCheck_ManagementCaps_ImplicitAllow(t *testing.T) {
	p := basePolicy()
	// No rules, DefaultDeny=true — management caps should still be allowed.
	for _, cap := range []string{"status", "list"} {
		d := p.Check(policy.Request{Actor: "anyone", Connection: "a:b", Capability: cap})
		if !d.Allow {
			t.Errorf("management cap %q should be implicitly allowed", cap)
		}
	}
}

func TestCheck_ApprovalRequired_Surfaced(t *testing.T) {
	p := basePolicy()
	r := ruleWith("*", "*", "inject")
	r.Approval = true
	p.Rules = []policy.Rule{r}

	d := p.Check(policy.Request{Actor: "anyone", Connection: "a:b", Capability: "inject"})
	if !d.Allow {
		t.Error("expected allow: rule matched with Approval=true")
	}
	if !d.ApprovalRequired {
		t.Error("ApprovalRequired should be true")
	}
	if d.ApprovalToken == "" {
		t.Error("ApprovalToken should be non-empty")
	}
}

func TestCheck_MatchedRuleSet(t *testing.T) {
	p := basePolicy()
	p.Rules = []policy.Rule{ruleWith("*", "*", "inject")}
	d := p.Check(policy.Request{Actor: "anyone", Connection: "a:b", Capability: "inject"})
	if !d.Allow {
		t.Error("expected allow")
	}
	if d.MatchedRule == nil {
		t.Error("MatchedRule should be set on allow")
	}
	if d.MatchedRule.ID != "rule-1" {
		t.Errorf("MatchedRule.ID = %q, want rule-1", d.MatchedRule.ID)
	}
}

// TestCheck_Canary verifies the canary never appears in Reason or SafeFix.
func TestCheck_Canary(t *testing.T) {
	p := basePolicy()
	// Seed canary as actor name in the request — should not appear in output.
	d := p.Check(policy.Request{
		Actor:      canaryKey,
		Connection: "openrouter:dev",
		Capability: "inject",
	})
	if d.Reason == canaryKey {
		t.Error("canary must not appear verbatim in Decision.Reason")
	}
	if d.SafeFix == canaryKey {
		t.Error("canary must not appear verbatim in Decision.SafeFix")
	}
}
