package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/trust"
)

func scWritePolicy(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_Rejections(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"malformed json", "{", "parse"},
		{"removed runtime", `{"rules":[{"id":"r","runtime":"direct_run"}]}`, "invalid runtime"},
		{"unknown runtime", `{"rules":[{"id":"r","runtime":"teleport"}]}`, "invalid runtime"},
		{"rate limit not enforced", `{"rules":[{"id":"r","rate_limit":{}}]}`, "rate_limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(scWritePolicy(t, tc.body, 0o600))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q error, got %v", tc.want, err)
			}
		})
	}

	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil || !strings.Contains(err.Error(), "stat") {
		t.Fatalf("missing file: %v", err)
	}
}

func TestLoad_RejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on windows")
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o660, 0o400} {
		_, err := Load(scWritePolicy(t, `{"rules":[]}`, mode))
		if err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
			t.Errorf("mode %04o: want unsafe permissions error, got %v", mode, err)
		}
	}
}

func TestLoad_UnreadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission semantics")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permissions")
	}
	path := scWritePolicy(t, `{}`, 0o600)
	dir := filepath.Dir(path)
	// A 0600 directory entry that is itself a directory cannot be read as a file.
	sub := filepath.Join(dir, "asdir")
	if err := os.Mkdir(sub, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	if _, err := Load(sub); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("want read error, got %v", err)
	}
}

func TestSave_RoundTripAndErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	before := time.Now().UTC().Add(-time.Second)
	if err := Save(path, Policy{DefaultDeny: true, Rules: []Rule{{ID: "r1", Actor: "a", Runtime: "gateway_typed"}}}); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !p.DefaultDeny || len(p.Rules) != 1 || p.Rules[0].ID != "r1" || p.UpdatedAt.Before(before) {
		t.Fatalf("round trip mismatch: %+v", p)
	}

	if err := Save(filepath.Join(dir, "missing", "p.json"), Policy{}); err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("want write error, got %v", err)
	}
	bad := Policy{Rules: []Rule{{ID: "r", Budget: []byte("{not json")}}}
	if err := Save(filepath.Join(dir, "bad.json"), bad); err == nil || !strings.Contains(err.Error(), "marshal") {
		t.Fatalf("want marshal error, got %v", err)
	}
}

func TestRuleMatches_InvalidRuleRuntimeNeverMatches(t *testing.T) {
	rule := Rule{Actor: "*", Connections: []string{"*"}, Capabilities: []string{"*"}, Runtime: "direct_run"}
	if ruleMatches(rule, Request{Actor: "a", Connection: "c", Capability: "x", Runtime: "direct_run"}) {
		t.Fatal("removed runtime in rule matched")
	}
	p := Policy{DefaultDeny: true, Rules: []Rule{rule}}
	if d := p.Check(Request{Actor: "a", Connection: "c", Capability: "x"}); d.Allow {
		t.Fatalf("default deny bypassed: %+v", d)
	}
}

func TestCheck_ConnectionAndCapabilityMustMatch(t *testing.T) {
	p := Policy{DefaultDeny: true, Rules: []Rule{{
		ID: "r", Actor: "claude-*", Connections: []string{"openrouter:*"}, Capabilities: []string{"openrouter.chat.*"},
	}}}
	cases := []struct {
		name  string
		req   Request
		allow bool
	}{
		{"all match", Request{Actor: "claude-code", Connection: "openrouter:dev", Capability: "openrouter.chat.create"}, true},
		{"wrong connection", Request{Actor: "claude-code", Connection: "openai:dev", Capability: "openrouter.chat.create"}, false},
		{"wrong capability", Request{Actor: "claude-code", Connection: "openrouter:dev", Capability: "openrouter.keys.create"}, false},
		{"wrong actor", Request{Actor: "cursor", Connection: "openrouter:dev", Capability: "openrouter.chat.create"}, false},
		{"empty connection", Request{Actor: "claude-code", Capability: "openrouter.chat.create"}, false},
	}
	for _, tc := range cases {
		d := p.Check(tc.req)
		if d.Allow != tc.allow {
			t.Errorf("%s: allow=%v want %v (%s)", tc.name, d.Allow, tc.allow, d.Reason)
		}
		if !tc.allow && d.Reason != "no rule matches request" {
			t.Errorf("%s: reason %q", tc.name, d.Reason)
		}
	}
}

func TestCheck_LLMSessionRuntimeOverrides(t *testing.T) {
	base := Rule{ID: "r", Actor: "*", Connections: []string{"*"}, Capabilities: []string{"svc.write"}}
	req := Request{Actor: "a", Connection: "c", Capability: "svc.write", LLMSession: true}

	cases := []struct {
		name        string
		llm         map[string]string
		runtime     string
		allow       bool
		approval    bool
		matchedRule bool
	}{
		{"deny", map[string]string{"direct_classic": "deny"}, "direct_classic", false, false, false},
		{"approval required", map[string]string{"direct_classic": "approval_required"}, "direct_classic", true, true, false},
		{"explicit allow falls through to rule", map[string]string{"direct_classic": "allow"}, "direct_classic", true, false, true},
		{"absent key falls through", map[string]string{"gateway_typed": "deny"}, "direct_classic", true, false, true},
		{"no overrides", nil, "gateway_typed", true, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := base
			rule.LLMSessions = tc.llm
			r := req
			r.Runtime = tc.runtime
			d := Policy{DefaultDeny: true, Rules: []Rule{rule}}.Check(r)
			if d.Allow != tc.allow || d.ApprovalRequired != tc.approval || (d.MatchedRule != nil) != tc.matchedRule {
				t.Fatalf("got %+v", d)
			}
			if !tc.allow && !strings.Contains(d.Reason, "denied by rule.LLMSessions") {
				t.Fatalf("reason = %q", d.Reason)
			}
		})
	}
}

func TestCheck_ApprovalRuleRejectsStalePresenceProof(t *testing.T) {
	rule := Rule{
		ID: "r", Actor: "*", Connections: []string{"*"}, Capabilities: []string{"svc.write"},
		Approval:        true,
		ApprovalRootReq: &RootRequirement{MaxAgeSec: 30},
	}
	p := Policy{DefaultDeny: true, Rules: []Rule{rule}}
	req := Request{Actor: "a", Connection: "c", Capability: "svc.write"}

	req.PresenceProof = &trust.PresenceProof{Method: "fido2", ConfirmedAt: time.Now().Add(-time.Hour), RootID: "r1"}
	d := p.Check(req)
	if d.Allow || !strings.Contains(d.Reason, "stale") {
		t.Fatalf("stale proof: %+v", d)
	}

	req.PresenceProof = &trust.PresenceProof{Method: "fido2", ConfirmedAt: time.Now(), RootID: "r1"}
	d = p.Check(req)
	if !d.Allow || !d.ApprovalRequired || d.ApprovalRootReq == nil || d.ApprovalToken == "" {
		t.Fatalf("fresh proof: %+v", d)
	}
}
