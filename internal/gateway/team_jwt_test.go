package gateway_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/team/ci"
)

func TestBuildTeamClaims_ValueFree(t *testing.T) {
	teamID := "team-abc"
	memberID := "alice@example.com"
	role := "developer"

	claims := gateway.BuildTeamClaims(teamID, memberID, role, "")

	// TeamID may be non-sensitive (it's an opaque ID), but MemberIDHMAC must not contain raw email.
	if strings.Contains(claims.MemberIDHMAC, "alice@") {
		t.Error("MemberIDHMAC contains raw email — value-free invariant violated")
	}
	if claims.MemberIDHMAC == "" {
		t.Error("MemberIDHMAC should not be empty")
	}
	if claims.Role != role {
		t.Errorf("Role = %q, want %q", claims.Role, role)
	}
	if claims.TeamID != teamID {
		t.Errorf("TeamID = %q, want %q", claims.TeamID, teamID)
	}
}

func TestBuildTeamClaims_WithApprovalRoot(t *testing.T) {
	claims := gateway.BuildTeamClaims("team-x", "member-1", "admin", "root-id-secret")

	if claims.ApprovalRootHMAC == "" {
		t.Error("ApprovalRootHMAC should not be empty when approvalRootID is provided")
	}
	if strings.Contains(claims.ApprovalRootHMAC, "root-id-secret") {
		t.Error("ApprovalRootHMAC contains raw root ID — value-free invariant violated")
	}
}

func TestBuildCIClaims_ValueFree(t *testing.T) {
	identity := ci.Identity{
		Provider: ci.ProviderGitHubActions,
		Subject:  "repo:myorg/myrepo:ref:refs/heads/main",
		Repo:     "myorg/myrepo",
		Branch:   "main",
		Workflow: "ci.yml",
	}

	claims := gateway.BuildCIClaims("team-test", identity)

	if claims.CIProvider != string(ci.ProviderGitHubActions) {
		t.Errorf("CIProvider = %q, want github-actions", claims.CIProvider)
	}
	// Repo must be HMACd.
	if strings.Contains(claims.CIRepo, "myorg/myrepo") {
		t.Error("CIRepo contains raw repo — value-free invariant violated")
	}
	if claims.CIRepo == "" {
		t.Error("CIRepo should not be empty")
	}
	// Branch must be HMACd.
	if claims.CIBranch == "main" {
		t.Error("CIBranch should be HMACd, not raw branch name")
	}
}

func TestBuildTeamClaims_Stable(t *testing.T) {
	// Same inputs should produce same HMACs.
	c1 := gateway.BuildTeamClaims("team-a", "member-1", "developer", "")
	c2 := gateway.BuildTeamClaims("team-a", "member-1", "developer", "")
	if c1.MemberIDHMAC != c2.MemberIDHMAC {
		t.Errorf("BuildTeamClaims not stable: %q != %q", c1.MemberIDHMAC, c2.MemberIDHMAC)
	}

	// Different teamID should produce different HMAC.
	c3 := gateway.BuildTeamClaims("team-b", "member-1", "developer", "")
	if c1.MemberIDHMAC == c3.MemberIDHMAC {
		t.Error("BuildTeamClaims should produce different HMAC for different teamID")
	}
}
