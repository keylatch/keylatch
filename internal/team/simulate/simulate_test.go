package simulate_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/orgpolicy"
	"github.com/keylatch/keylatch/internal/team/simulate"
)

func init() {
	orgpolicy.ResetForTest()
}

func newMember(role team.Role) team.Member {
	return team.Member{
		ID:     "test-member",
		HMAC:   "hmac-member",
		Role:   role,
		Status: team.MemberActive,
	}
}

func installDenyBundle(t *testing.T, capability string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", dir)
	orgpolicy.ResetForTest()

	b := &orgpolicy.OrgBundle{
		SchemaVersion:   "1",
		BundleID:        "test-bundle",
		Version:         1,
		TeamID:          "team-test",
		Issuer:          "test",
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(24 * time.Hour),
		AllowedEnvelope: orgpolicy.AllowedEnvelope{},
		BaselineDeny:    []string{capability},
	}
	orgpolicy.SignBundle(b)

	data, _ := json.MarshalIndent(b, "", " ")
	p := filepath.Join(dir, "bundle.json")
	_ = os.WriteFile(p, data, 0o600)
	_ = orgpolicy.Install(context.Background(), p, "")
}

func TestSimulate_OrgPolicyBaselineDenies(t *testing.T) {
	installDenyBundle(t, "write")

	member := newMember(team.RoleDeveloper)
	result, err := simulate.Simulate(context.Background(), "write", "production", member)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if result.Decision != "deny" {
		t.Errorf("Decision = %q, want deny", result.Decision)
	}
	if !result.OrgOverride {
		t.Error("OrgOverride should be true when org policy denies")
	}
}

func TestSimulate_ApprovalRequired_TwoPerson(t *testing.T) {
	// Clear org policy.
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", t.TempDir())
	orgpolicy.ResetForTest()

	// High-risk capability in production requires approval.
	member := newMember(team.RoleDeveloper)
	result, err := simulate.Simulate(context.Background(), "write", "production", member)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	// write in production should be approval_required due to risk assessment.
	if result.Decision != "approval_required" {
		t.Errorf("Decision = %q, want approval_required for write in production", result.Decision)
	}
}

func TestExplain_MentionsRuleID(t *testing.T) {
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", t.TempDir())
	orgpolicy.ResetForTest()

	member := newMember(team.RoleDeveloper)
	result, err := simulate.Simulate(context.Background(), "read", "staging", member)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	result.RuleID = "rule-abc123"

	explanation := simulate.Explain(result)
	if !strings.Contains(explanation, "rule-abc123") {
		t.Errorf("Explain output does not contain rule ID: %q", explanation)
	}
	if !strings.Contains(explanation, "Decision:") {
		t.Errorf("Explain output missing 'Decision:' field: %q", explanation)
	}
}

func TestRiskReport_ReturnsResultForEachCapability(t *testing.T) {
	t.Setenv("KEYLATCH_ORG_POLICY_DIR", t.TempDir())
	orgpolicy.ResetForTest()

	caps := []string{"read", "write", "delete", "list"}
	member := newMember(team.RoleDeveloper)
	results, err := simulate.RiskReport(context.Background(), caps, member)
	if err != nil {
		t.Fatalf("RiskReport: %v", err)
	}
	if len(results) != len(caps) {
		t.Errorf("RiskReport returned %d results, want %d", len(results), len(caps))
	}
}
