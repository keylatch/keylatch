package policy_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/policy"
	"github.com/keylatch/keylatch/internal/team/orgpolicy"
)

func makeOrgDenyBundle(t *testing.T, capability string) string {
	t.Helper()
	dir := t.TempDir()
	b := &orgpolicy.OrgBundle{
		SchemaVersion:   "1",
		BundleID:        "compose-test-bundle",
		Version:         100,
		TeamID:          "team-compose",
		Issuer:          "test",
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(24 * time.Hour),
		AllowedEnvelope: orgpolicy.AllowedEnvelope{},
		BaselineDeny:    []string{capability},
	}
	orgpolicy.SignBundle(b)
	data, _ := json.MarshalIndent(b, "", " ")
	path := filepath.Join(dir, "bundle.json")
	_ = os.WriteFile(path, data, 0o600)
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()
	if err := orgpolicy.Install(context.Background(), path, ""); err != nil {
		t.Fatalf("Install org bundle: %v", err)
	}
	return dir
}

// TestOrgCompose_BaselineDenyBeforeLocalMatch verifies that org baseline deny
// overrides a local allow via the OrgComposeHook integration in policy.Check.
func TestOrgCompose_BaselineDenyBeforeLocalMatch(t *testing.T) {
	makeOrgDenyBundle(t, "inject")

	// Wire OrgComposeHook.
	origHook := policy.OrgComposeHook
	policy.OrgComposeHook = func(req policy.Request) (policy.Decision, bool) {
		bundle := orgpolicy.Active(context.Background())
		if bundle == nil {
			return policy.Decision{}, false
		}
		local := orgpolicy.Decision{Allow: true, Reason: "local default"}
		result := orgpolicy.Compose(context.Background(), bundle, local, req.Capability, "")
		if !result.Allow {
			return policy.Decision{Allow: false, Reason: result.Reason}, true
		}
		return policy.Decision{}, false
	}
	t.Cleanup(func() {
		policy.OrgComposeHook = origHook
		orgpolicy.ResetForTest()
	})

	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   false,
		Rules: []policy.Rule{
			{
				ID:           "allow-inject",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"inject"},
				CreatedAt:    time.Now(),
			},
		},
	}

	d := p.Check(policy.Request{
		Actor:      "human-shell",
		Connection: "openrouter:dev",
		Capability: "inject",
	})
	if d.Allow {
		t.Error("org baseline deny should override local allow; got Allow=true")
	}
}

// TestOrgCompose_OrgAllowLocalDeny verifies that local-deny wins over org-allow.
func TestOrgCompose_OrgAllowLocalDeny(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()

	// No org bundle installed = org allows everything.
	// Local policy: DefaultDeny=true, no rules.
	origHook := policy.OrgComposeHook
	policy.OrgComposeHook = func(req policy.Request) (policy.Decision, bool) {
		bundle := orgpolicy.Active(context.Background())
		if bundle == nil {
			return policy.Decision{}, false
		}
		local := orgpolicy.Decision{Allow: true}
		result := orgpolicy.Compose(context.Background(), bundle, local, req.Capability, "")
		if !result.Allow {
			return policy.Decision{Allow: false, Reason: result.Reason}, true
		}
		return policy.Decision{}, false
	}
	t.Cleanup(func() {
		policy.OrgComposeHook = origHook
		orgpolicy.ResetForTest()
	})

	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true, // local deny
	}
	d := p.Check(policy.Request{
		Actor:      "human-shell",
		Connection: "openrouter:dev",
		Capability: "read",
	})
	if d.Allow {
		t.Error("local deny should win; got Allow=true")
	}
}

// TestOrgCompose_OrgAllowLocalNarrow verifies that local narrowing wins.
func TestOrgCompose_OrgAllowLocalNarrow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()

	// No org bundle = org allows all.
	origHook := policy.OrgComposeHook
	policy.OrgComposeHook = func(req policy.Request) (policy.Decision, bool) {
		bundle := orgpolicy.Active(context.Background())
		if bundle == nil {
			return policy.Decision{}, false
		}
		local := orgpolicy.Decision{Allow: true}
		result := orgpolicy.Compose(context.Background(), bundle, local, req.Capability, "")
		if !result.Allow {
			return policy.Decision{Allow: false, Reason: result.Reason}, true
		}
		return policy.Decision{}, false
	}
	t.Cleanup(func() {
		policy.OrgComposeHook = origHook
		orgpolicy.ResetForTest()
	})

	// Local policy: only allow "inject" (narrower than org's "allow all").
	p := policy.Policy{
		SchemaVersion: 1,
		Mode:          policy.ModeEnforcing,
		DefaultDeny:   true,
		Rules: []policy.Rule{
			{
				ID:           "allow-inject-only",
				Actor:        "*",
				Connections:  []string{"*"},
				Capabilities: []string{"inject"},
				CreatedAt:    time.Now(),
			},
		},
	}

	// inject matches local rule → allow.
	d := p.Check(policy.Request{Actor: "human-shell", Connection: "a:b", Capability: "inject"})
	if !d.Allow {
		t.Error("inject matches local rule; expected Allow=true")
	}

	// read does not match local rule → local deny wins.
	d2 := p.Check(policy.Request{Actor: "human-shell", Connection: "a:b", Capability: "read"})
	if d2.Allow {
		t.Error("read not in local rules; local narrowing (deny) should win")
	}
}
