// Package gateway — team JWT claim helpers (Phase 12).
//
// Security invariants:
//   - All member IDs in JWT claims are HMACd (value-free output).
//   - CI OIDC claims are bound to the verified CI identity.
package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/keylatch/keylatch/internal/team/ci"
)

// TeamJWTClaims holds Phase 12 team-mode claims to add to a gateway JWT.
// All sensitive values are HMACd per the value-free output invariant.
type TeamJWTClaims struct {
	TeamID           string `json:"team_id,omitempty"`
	MemberIDHMAC     string `json:"member_id_hmac,omitempty"`
	Role             string `json:"role,omitempty"`
	ApprovalRootHMAC string `json:"approval_root_hmac,omitempty"`
}

// CIJWTClaims holds CI OIDC identity claims for a gateway JWT.
type CIJWTClaims struct {
	CIProvider string `json:"ci_provider,omitempty"`
	CIRepo     string `json:"ci_repo_hmac,omitempty"`     // HMACd
	CIBranch   string `json:"ci_branch_hmac,omitempty"`   // HMACd
	CIWorkflow string `json:"ci_workflow_hmac,omitempty"` // HMACd
	CISubject  string `json:"ci_subject_hmac,omitempty"`  // HMACd
}

// hmacClaim produces a stable HMAC of a sensitive JWT claim value.
func hmacClaim(teamID, value string) string {
	key := sha256ClaimKey(teamID)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

func sha256ClaimKey(teamID string) []byte {
	h := sha256.New()
	h.Write([]byte("keylatch/gateway/jwt-claim/v1/"))
	h.Write([]byte(teamID))
	return h.Sum(nil)
}

// BuildTeamClaims constructs a TeamJWTClaims for the given team context.
// teamID, memberID, and role are required; approvalRootID is optional (empty = omitted).
func BuildTeamClaims(teamID, memberID, role, approvalRootID string) TeamJWTClaims {
	claims := TeamJWTClaims{
		TeamID:       teamID,
		MemberIDHMAC: hmacClaim(teamID, memberID),
		Role:         role,
	}
	if approvalRootID != "" {
		claims.ApprovalRootHMAC = hmacClaim(teamID, approvalRootID)
	}
	return claims
}

// BuildCIClaims constructs CIJWTClaims from a verified CI identity.
// All sensitive values (repo, branch, workflow, subject) are HMACd.
func BuildCIClaims(teamID string, identity ci.Identity) CIJWTClaims {
	return CIJWTClaims{
		CIProvider: string(identity.Provider),
		CIRepo:     hmacClaim(teamID, identity.Repo),
		CIBranch:   hmacClaim(teamID, identity.Branch),
		CIWorkflow: hmacClaim(teamID, identity.Workflow),
		CISubject:  hmacClaim(teamID, identity.Subject),
	}
}
