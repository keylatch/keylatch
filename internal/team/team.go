// Package team implements team identity, membership, RBAC, and shared-secret coordination.
//
// Security invariants:
// - Value-free output: all output HMACs sensitive values (member emails, OIDC subjects, secret names, root IDs).
// Never emit raw values. Use HMACValue(teamID, raw) pattern.
// - Role enforcement happens at package layer, not CLI layer.
// - Self-approval is blocked — approver must differ from requester.
package team

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Role defines access level for a team member.
type Role string

const (
	RoleOwner     Role = "owner"
	RoleAdmin     Role = "admin"
	RoleDeveloper Role = "developer"
	RoleViewer    Role = "viewer"
)

// MemberStatus describes the lifecycle state of a team member.
type MemberStatus string

const (
	MemberActive    MemberStatus = "active"
	MemberSuspended MemberStatus = "suspended"
	MemberRemoved   MemberStatus = "removed"
)

// Member represents a team member.
// The HMAC field is the HMAC of the member's email — raw email is never stored.
type Member struct {
	ID           string       `json:"id"`   // ULID-shaped opaque ID
	HMAC         string       `json:"hmac"` // HMAC of email — never raw email stored
	Role         Role         `json:"role"`
	AgePublicKey string       `json:"age_public_key"` // X25519 public key for shared-secret distribution
	TrustRoots   []string     `json:"trust_roots"`    // pinned root IDs (HMACd)
	JoinedAt     time.Time    `json:"joined_at"`
	Status       MemberStatus `json:"status"`
}

// Team represents a keylatch team.
type Team struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Members      []Member  `json:"members"`
	CosignPubKey string    `json:"cosign_pub_key"` // for org policy bundle verification
	SyncRepoURL  string    `json:"sync_repo_url"`  // bare Git repo for team sync
	CreatedAt    time.Time `json:"created_at"`
}

// Sentinel errors.
var (
	ErrTeamNotConfigured = errors.New("team not configured")
	ErrMemberNotFound    = errors.New("member not found")
	ErrRoleInsufficient  = errors.New("insufficient role for this operation")
	ErrSelfApproval      = errors.New("self-approval is not permitted")
)

// HMACValue produces a stable, team-scoped HMAC of a sensitive value.
// Use for all external output — never emit raw emails, subjects, or IDs.
func HMACValue(teamID, value string) string {
	key := hmacTeamKey(teamID)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// hmacTeamKey derives a 32-byte HMAC key scoped to teamID using HKDF-SHA256.
// N-9: replaces the weaker SHA-256-over-known-prefix derivation with proper HKDF.
func hmacTeamKey(teamID string) []byte {
	h := hkdf.New(sha256.New, []byte(teamID), []byte("keylatch/team/hmac-key/v1"), nil)
	key := make([]byte, 32)
	_, _ = io.ReadFull(h, key)
	return key
}
