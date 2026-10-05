package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/policy"
)

func cdPolicy(t *testing.T, rules ...policy.Rule) string {
	t.Helper()
	dir := cdIsolate(t)
	p := filepath.Join(dir, "policy.json")
	if rules == nil {
		rules = []policy.Rule{}
	}
	if err := policy.Save(p, policy.Policy{SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	return p
}

func cdLoadPolicy(t *testing.T, p string) policy.Policy {
	t.Helper()
	got, err := policy.Load(p)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return got
}

func TestPolicyAllow_PersistsAllRuleFields(t *testing.T) {
	p := cdPolicy(t)
	r := cdExec(t, newPolicyAllowCmd(), nil, "claude", "openai",
		"--capability", "inject", "--command", "curl *", "--cwd", "/work/*", "--ttl", "90m",
		"--approval", "--runtime", "gateway_typed", "--note", "ci")
	if r.e != nil {
		t.Fatalf("allow: %v", r.e)
	}
	got := cdLoadPolicy(t, p)
	if len(got.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(got.Rules))
	}
	rule := got.Rules[0]
	if !strings.Contains(r.out, "rule "+rule.ID+" added") {
		t.Fatalf("output %q does not name rule %s", r.out, rule.ID)
	}
	if rule.Actor != "claude" || rule.Connections[0] != "openai" || rule.Capabilities[0] != "inject" ||
		rule.Commands[0] != "curl *" || rule.CWDs[0] != "/work/*" || rule.MaxTTLSeconds != 5400 ||
		!rule.Approval || string(rule.Runtime) != "gateway_typed" || rule.Note != "ci" {
		t.Fatalf("unexpected rule %+v", rule)
	}
	if !got.DefaultDeny || got.Mode != policy.ModeEnforcing {
		t.Fatal("adding a rule must not weaken default-deny enforcing mode")
	}
}

func TestPolicyAllow_MinimalRuleOmitsOptionalFilters(t *testing.T) {
	p := cdPolicy(t)
	if r := cdExec(t, newPolicyAllowCmd(), nil, "claude", "openai"); r.e != nil {
		t.Fatal(r.e)
	}
	rule := cdLoadPolicy(t, p).Rules[0]
	if rule.Commands != nil || rule.CWDs != nil || rule.MaxTTLSeconds != 0 || rule.Approval {
		t.Fatalf("unexpected optional filters %+v", rule)
	}
}

func TestPolicyAllow_RejectsBadInputWithoutWriting(t *testing.T) {
	p := cdPolicy(t)
	before, _ := os.ReadFile(p)
	r := cdExec(t, newPolicyAllowCmd(), nil, "claude", "openai", "--ttl", "soon")
	if r.e == nil || !strings.Contains(r.e.Error(), "invalid --ttl") {
		t.Fatalf("err = %v", r.e)
	}
	if after, _ := os.ReadFile(p); string(after) != string(before) {
		t.Fatal("policy must be unchanged after a rejected rule")
	}
}

func TestPolicyCommands_FailClosedOnUnsafePolicyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not enforced on Windows")
	}
	p := cdPolicy(t)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"allow": {"claude", "openai"},
		"check": {"claude", "openai", "--json"},
		"list":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			c := newPolicyAllowCmd()
			switch name {
			case "check":
				c = newPolicyCheckCmd()
			case "list":
				c = newPolicyListCmd()
			}
			r := cdExec(t, c, nil, args...)
			if r.e == nil || !strings.Contains(r.e.Error(), "unsafe permissions") {
				t.Fatalf("err = %v, want unsafe permissions", r.e)
			}
			if strings.Contains(r.out, "ALLOW") || strings.Contains(r.out, "added") {
				t.Fatalf("no decision may be produced from an unsafe policy: %q", r.out)
			}
		})
	}
}

func TestPolicyList_TableAndDeterministicJSON(t *testing.T) {
	cdPolicy(t, policy.Rule{ID: "r-1", Actor: "claude", Connections: []string{"openai", "github"},
		Capabilities: []string{"inject"}, Commands: []string{"curl *"}, Runtime: "gateway_typed", Approval: true, Note: "n1"})

	r := cdExec(t, newPolicyListCmd(), nil)
	if r.e != nil {
		t.Fatal(r.e)
	}
	if !strings.Contains(r.out, "r-1") || !strings.Contains(r.out, "openai,github") || !strings.Contains(r.out, "gateway_typed") {
		t.Fatalf("table missing rule: %q", r.out)
	}

	r = cdExec(t, newPolicyListCmd(), nil, "--json")
	var rows []map[string]any
	if err := json.Unmarshal([]byte(r.out), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("json: %v %q", err, r.out)
	}
	if rows[0]["id"] != "r-1" || rows[0]["approval"] != true || rows[0]["note"] != "n1" {
		t.Fatalf("unexpected row %v", rows[0])
	}
	if _, ok := rows[0]["created_at"]; ok {
		t.Fatal("json listing must not include timestamps")
	}
}

type cdDecision struct {
	Allow            bool   `json:"allow"`
	Reason           string `json:"reason"`
	SafeFix          string `json:"safe_fix"`
	ApprovalRequired bool   `json:"approval_required"`
	MatchedRuleID    string `json:"matched_rule_id"`
}

func cdCheck(t *testing.T, args ...string) cdDecision {
	t.Helper()
	r := cdExec(t, newPolicyCheckCmd(), nil, append([]string{"--json"}, args...)...)
	if r.e != nil {
		t.Fatalf("check: %v", r.e)
	}
	var d cdDecision
	if err := json.Unmarshal([]byte(r.out), &d); err != nil {
		t.Fatalf("decode decision: %v %q", err, r.out)
	}
	return d
}

func TestPolicyCheck_Decisions(t *testing.T) {
	rules := []policy.Rule{
		{ID: "plain", Actor: "ci", Connections: []string{"openai"}, Capabilities: []string{"inject"}},
		{ID: "needs-approval", Actor: "ci", Connections: []string{"github"}, Capabilities: []string{"inject"}, Approval: true},
		{ID: "cmd", Actor: "ci", Connections: []string{"stripe"}, Capabilities: []string{"inject"}, Commands: []string{"curl"}},
	}

	t.Run("default deny when nothing matches", func(t *testing.T) {
		cdPolicy(t, rules...)
		d := cdCheck(t, "someone-else", "openai")
		if d.Allow || d.Reason != "no rule matches request" || d.SafeFix == "" {
			t.Fatalf("unexpected decision %+v", d)
		}
	})
	t.Run("matching rule allows", func(t *testing.T) {
		cdPolicy(t, rules...)
		d := cdCheck(t, "ci", "openai")
		if !d.Allow || d.MatchedRuleID != "plain" || d.ApprovalRequired {
			t.Fatalf("unexpected decision %+v", d)
		}
	})
	t.Run("approval rule requires approval", func(t *testing.T) {
		cdPolicy(t, rules...)
		d := cdCheck(t, "ci", "github")
		if !d.Allow || !d.ApprovalRequired || d.MatchedRuleID != "needs-approval" {
			t.Fatalf("unexpected decision %+v", d)
		}
	})
	t.Run("command filter honours argv after dash", func(t *testing.T) {
		cdPolicy(t, rules...)
		if d := cdCheck(t, "ci", "stripe", "--", "curl", "-s"); !d.Allow || d.MatchedRuleID != "cmd" {
			t.Fatalf("curl must match: %+v", d)
		}
		if d := cdCheck(t, "ci", "stripe", "--", "wget"); d.Allow {
			t.Fatalf("wget must not match: %+v", d)
		}
	})
	t.Run("read capability denied in agent session", func(t *testing.T) {
		cdPolicy(t, policy.Rule{ID: "rd", Actor: "*", Connections: []string{"*"}, Capabilities: []string{"*"}})
		t.Setenv("CREDENTIALS_LLM_SESSION", "1")
		d := cdCheck(t, "ci", "openai", "--capability", "read")
		if d.Allow || !strings.Contains(d.Reason, "denied in LLM sessions") {
			t.Fatalf("unexpected decision %+v", d)
		}
	})
}

func TestPolicyCheck_PermissiveModeInAgentSessionFailsClosed(t *testing.T) {
	dir := cdIsolate(t)
	p := filepath.Join(dir, "policy.json")
	if err := policy.Save(p, policy.Policy{SchemaVersion: 1, Mode: policy.ModePermissive, Rules: []policy.Rule{}}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_LLM_SESSION", "1")
	d := cdCheck(t, "claude", "openai")
	if d.Allow || !strings.Contains(d.Reason, "invariant violation") || d.SafeFix != "use ModeEnforcing in LLM sessions" {
		t.Fatalf("permissive policy in an agent session must deny: %+v", d)
	}
}

func TestPolicyCheck_TextAllow(t *testing.T) {
	cdPolicy(t, policy.Rule{ID: "needs-approval", Actor: "ci", Connections: []string{"github"}, Capabilities: []string{"inject"}, Approval: true})
	r := cdExec(t, newPolicyCheckCmd(), nil, "ci", "github")
	if r.e != nil {
		t.Fatal(r.e)
	}
	if strings.TrimSpace(r.out) != "ALLOW (rule: needs-approval) [approval required]" {
		t.Fatalf("unexpected output %q", r.out)
	}
}

func TestPolicyRemove_DeletesOnlyTargetRule(t *testing.T) {
	p := cdPolicy(t,
		policy.Rule{ID: "keep", Actor: "a", Connections: []string{"c"}, Capabilities: []string{"inject"}},
		policy.Rule{ID: "drop", Actor: "b", Connections: []string{"c"}, Capabilities: []string{"inject"}})
	r := cdExec(t, newPolicyRemoveCmd(), nil, "drop")
	if r.e != nil || !strings.Contains(r.out, "rule drop removed") {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
	got := cdLoadPolicy(t, p)
	if len(got.Rules) != 1 || got.Rules[0].ID != "keep" {
		t.Fatalf("unexpected remaining rules %+v", got.Rules)
	}
}

func TestPolicyRemove_MissingPolicyErrors(t *testing.T) {
	cdIsolate(t)
	if r := cdExec(t, newPolicyRemoveCmd(), nil, "any"); r.e == nil {
		t.Fatal("remove without a policy file must fail")
	}
}

func TestPolicyInit_ThenAllowAndList(t *testing.T) {
	cdIsolate(t)
	group := newPolicyCmd()
	if r := cdExec(t, group, nil, "init"); r.e != nil {
		t.Fatal(r.e)
	}
	if r := cdExec(t, newPolicyCmd(), nil, "allow", "claude", "openai"); r.e != nil {
		t.Fatal(r.e)
	}
	r := cdExec(t, newPolicyCmd(), nil, "list", "--json")
	if r.e != nil || !strings.Contains(r.out, `"actor": "claude"`) {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
}

func TestPolicyInit_MkdirFailure(t *testing.T) {
	dir := cdIsolate(t)
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYLATCH_POLICY_PATH", filepath.Join(blocker, "sub", "policy.json"))
	r := cdExec(t, newPolicyInitCmd(), nil)
	if r.e == nil || !strings.Contains(r.e.Error(), "mkdir") {
		t.Fatalf("err = %v, want mkdir failure", r.e)
	}
}
