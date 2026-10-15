package enforce

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/grant"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
)

type fixture struct {
	dir string
	e   *Enforcer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	return &fixture{dir: dir, e: &Enforcer{
		PolicyPath: filepath.Join(dir, "policy.json"),
		PolicyDir:  filepath.Join(dir, "policy.d"),
		GrantPath:  filepath.Join(dir, "grants.json"),
	}}
}

func (f *fixture) writeRules(t *testing.T, json string) {
	t.Helper()
	if err := os.WriteFile(f.e.PolicyPath, []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) writeDocs(t *testing.T, docs ...string) {
	t.Helper()
	set := map[string]connpolicy.Document{}
	for _, s := range docs {
		d, err := connpolicy.Parse([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		set[d.Connection] = d
	}
	if err := (connpolicy.Store{Dir: f.e.PolicyDir}).Replace(set); err != nil {
		t.Fatal(err)
	}
}

const gatewayOnlyAgent = `{"schema_version": 2, "connection": "openrouter", "max_ttl": "10m",
  "callers": {"agent": {"allow": true, "runtimes": ["gateway_typed", "gateway_sdk"]}, "human": {"allow": true}}}`

func TestMissingPolicyDenies(t *testing.T) {
	f := newFixture(t)
	d := f.e.Decide(context.Background(), Request{Connection: "openrouter", Caller: callerkind.Human})
	if d.Allow {
		t.Fatal("allowed with no policy at all")
	}
	if want := "no policy for openrouter: run `keylatch policy init`"; d.Reason != want {
		t.Fatalf("reason = %q, want %q", d.Reason, want)
	}
}

func TestDefaultDenyWhenOmitted(t *testing.T) {
	f := newFixture(t)
	req := Request{Connection: "openrouter", Caller: callerkind.Human, Actor: "dev"}

	f.writeRules(t, `{"schema_version": 1, "mode": "enforcing", "rules": []}`)
	if f.e.Decide(context.Background(), req).Allow {
		t.Fatal("a rules file without default_deny allowed an unmatched request")
	}

	f.writeRules(t, `{"schema_version": 1, "mode": "enforcing", "default_deny": false, "rules": []}`)
	if !f.e.Decide(context.Background(), req).Allow {
		t.Fatal("an explicit default_deny=false no longer allows")
	}

	f.writeRules(t, `{"schema_version": 1, "mode": "enforcing", "default_deny": true, "rules": []}`)
	if f.e.Decide(context.Background(), req).Allow {
		t.Fatal("default_deny=true allowed an unmatched request")
	}
}

func TestAgentAllowedOnlyUnderListedRuntimes(t *testing.T) {
	f := newFixture(t)
	f.writeDocs(t, gatewayOnlyAgent)
	ctx := context.Background()

	for _, rt := range []string{"gateway_typed", "gateway_sdk"} {
		if d := f.e.Decide(ctx, Request{Connection: "openrouter", Runtime: rt, Caller: callerkind.Agent}); !d.Allow {
			t.Errorf("agent under %s denied: %s", rt, d.Reason)
		}
	}
	for _, rt := range []string{"direct_brokered", "direct_classic", "gateway_proxy", ""} {
		if d := f.e.Decide(ctx, Request{Connection: "openrouter", Runtime: rt, Caller: callerkind.Agent}); d.Allow {
			t.Errorf("agent under %q allowed", rt)
		}
	}
	if d := f.e.Decide(ctx, Request{Connection: "openrouter", Runtime: "gateway_typed", Caller: callerkind.Host}); d.Allow {
		t.Error("host allowed by a document that lists only agent and human")
	}

	// A connection without an agent entry denies the agent.
	f.writeDocs(t, `{"schema_version": 2, "connection": "openrouter", "callers": {"human": {"allow": true}}}`)
	if d := f.e.Decide(ctx, Request{Connection: "openrouter", Runtime: "gateway_typed", Caller: callerkind.Agent}); d.Allow {
		t.Error("agent allowed without a callers.agent entry")
	}
}

func TestDocumentRulesAndFallbackPrecedence(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.writeRules(t, `{"schema_version": 1, "mode": "enforcing", "default_deny": true, "rules": [
	  {"id": "r1", "actor": "dev", "connections": ["stripe"], "capabilities": ["inject"], "created_at": "2026-10-01T00:00:00Z"}]}`)
	f.writeDocs(t,
		`{"schema_version": 2, "connection": "*", "callers": {"human": {"allow": true}}}`,
		`{"schema_version": 2, "connection": "openrouter", "callers": {"human": "deny"}}`,
	)

	// The connection's own document decides, even against a fallback that allows.
	if d := f.e.Decide(ctx, Request{Connection: "openrouter", Caller: callerkind.Human, Actor: "dev"}); d.Allow || d.Source != "connection-policy" {
		t.Errorf("own document: %+v", d)
	}
	// A rule allows a connection with no document of its own.
	if d := f.e.Decide(ctx, Request{Connection: "stripe", Caller: callerkind.Agent, Actor: "dev"}); !d.Allow || d.Source != "rules" || d.RuleID != "r1" {
		t.Errorf("rule: %+v", d)
	}
	// No document, no matching rule: the fallback decides.
	if d := f.e.Decide(ctx, Request{Connection: "vercel", Caller: callerkind.Human, Actor: "dev"}); !d.Allow || d.Source != "fallback-policy" {
		t.Errorf("fallback allow: %+v", d)
	}
	if d := f.e.Decide(ctx, Request{Connection: "vercel", Caller: callerkind.Agent, Actor: "dev"}); d.Allow {
		t.Errorf("fallback allowed an agent: %+v", d)
	}
}

func TestUnreadablePolicyDenies(t *testing.T) {
	f := newFixture(t)
	f.writeDocs(t, gatewayOnlyAgent)
	if err := os.WriteFile(filepath.Join(f.e.PolicyDir, "openrouter.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := f.e.Decide(context.Background(), Request{Connection: "openrouter", Runtime: "gateway_typed", Caller: callerkind.Agent})
	if d.Allow || !strings.Contains(d.Reason, "cannot be read") {
		t.Fatalf("broken document: %+v", d)
	}

	f2 := newFixture(t)
	f2.writeRules(t, "not json")
	if d := f2.e.Decide(context.Background(), Request{Connection: "x", Caller: callerkind.Human}); d.Allow {
		t.Fatalf("broken rules file allowed: %+v", d)
	}
}

func TestMaxTTLComesFromTheDocument(t *testing.T) {
	f := newFixture(t)
	f.writeDocs(t, gatewayOnlyAgent)
	d := f.e.Decide(context.Background(), Request{Connection: "openrouter", Runtime: "gateway_typed", Caller: callerkind.Agent})
	if d.MaxTTL != 10*time.Minute {
		t.Fatalf("MaxTTL = %v, want 10m", d.MaxTTL)
	}
}

func TestEmptyCallerCountsAsHost(t *testing.T) {
	f := newFixture(t)
	f.writeDocs(t, `{"schema_version": 2, "connection": "a", "callers": {"host": "deny", "human": {"allow": true}}}`)
	if d := f.e.Decide(context.Background(), Request{Connection: "a"}); d.Allow {
		t.Fatalf("a request with no caller kind was treated as human: %+v", d)
	}
}

func TestGrantNeedsPresenceToOverride(t *testing.T) {
	f := newFixture(t)
	f.writeDocs(t, `{"schema_version": 2, "connection": "stripe", "callers": {"agent": "deny"}}`)
	env := func(k string) string {
		switch k {
		case "KEYLATCH_GRANTS_PATH":
			return f.e.GrantPath
		case "KEYLATCH_GRANTS_DIR":
			return filepath.Join(f.dir, "grants")
		case "KEYLATCH_GRANT_ACCESSOR_KEY_PATH":
			return filepath.Join(f.dir, "accessor.key")
		}
		return ""
	}
	ctx := context.Background()
	req := Request{Connection: "stripe", Runtime: "gateway_typed", Caller: callerkind.Agent, Actor: "claude-code"}

	if _, err := grant.Create(ctx, grant.GrantSpec{Actor: "claude-code", Connection: "stripe", Capability: "inject", TTL: time.Hour}, env); err != nil {
		t.Fatal(err)
	}
	if d := f.e.Decide(ctx, req); d.Allow {
		t.Fatalf("a grant issued without presence overrode a deny: %+v", d)
	}

	g, err := grant.Create(ctx, grant.GrantSpec{Actor: "claude-code", Connection: "stripe", Capability: "inject", TTL: time.Hour, PresenceDigest: "d3adbeef"}, env)
	if err != nil {
		t.Fatal(err)
	}
	d := f.e.Decide(ctx, req)
	if !d.Allow || d.Source != "grant" || d.GrantID != g.ID {
		t.Fatalf("a grant issued with presence did not override: %+v", d)
	}
	if d := f.e.Decide(ctx, Request{Connection: "stripe", Caller: callerkind.Agent, Actor: "someone-else"}); d.Allow {
		t.Fatalf("a grant for another actor applied: %+v", d)
	}
}

func TestSetDefaultAndAllowAll(t *testing.T) {
	restore := SetDefault(AllowAll())
	if !Decide(context.Background(), Request{Connection: "anything"}).Allow {
		t.Fatal("AllowAll default denied")
	}
	restore()
	t.Setenv("KEYLATCH_CONFIG_DIR", t.TempDir())
	t.Setenv("KEYLATCH_POLICY_PATH", "")
	if Decide(context.Background(), Request{Connection: "anything"}).Allow {
		t.Fatal("the real default allowed with no policy")
	}
}

func TestInjectedRulesWinOverTheFile(t *testing.T) {
	f := newFixture(t)
	f.writeRules(t, `{"schema_version": 1, "mode": "enforcing", "default_deny": false, "rules": []}`)
	f.e.Rules = &policy.Policy{SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true}
	if f.e.Decide(context.Background(), Request{Connection: "a", Caller: callerkind.Human, Actor: "dev"}).Allow {
		t.Fatal("the file was read although rules were injected")
	}
}

// A permissive policy must not panic the process for an agent request.
func TestPermissivePolicyForAgentDenies(t *testing.T) {
	f := newFixture(t)
	f.e.Rules = &policy.Policy{SchemaVersion: 1, Mode: policy.ModePermissive}
	d := f.e.Decide(context.Background(), Request{Connection: "a", Caller: callerkind.Agent, Actor: "claude-code"})
	if d.Allow || !strings.Contains(d.Reason, "invariant") {
		t.Fatalf("decision = %+v", d)
	}
}
