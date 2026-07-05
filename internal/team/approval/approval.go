// Package approval implements two-person and N-of-M approval workflows.
//
// Security invariants:
// - Self-approval is blocked — approver must differ from requester.
// - Two-person hardware approval unlocks LLM-session read blocks.
// - All JWT claims are value-free (member IDs are HMACd).
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/trust"
)

// ApprovalMode describes the approval quorum mode.
type ApprovalMode string

const (
	ModeTwoPerson ApprovalMode = "two_person"
	ModeNofM      ApprovalMode = "n_of_m"
)

// ApprovalStatus describes the state of an approval request.
type ApprovalStatus string

const (
	StatusPending  ApprovalStatus = "pending"
	StatusApproved ApprovalStatus = "approved"
	StatusDenied   ApprovalStatus = "denied"
	StatusExpired  ApprovalStatus = "expired"
)

// ApprovalRequest is a pending approval request.
type ApprovalRequest struct {
	ID            string          `json:"id"`
	Capability    string          `json:"capability"`
	Connection    string          `json:"connection"`
	RequesterHMAC string          `json:"requester_hmac"` // HMAC of requester member ID
	Mode          ApprovalMode    `json:"mode"`
	N             int             `json:"n"` // required approvals
	M             int             `json:"m"` // eligible approvers
	Approvals     []ApprovalEntry `json:"approvals"`
	Status        ApprovalStatus  `json:"status"`
	CreatedAt     time.Time       `json:"created_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

// ApprovalEntry records a single approval.
type ApprovalEntry struct {
	ApproverHMAC string    `json:"approver_hmac"` // HMAC of approver member ID
	ApprovedAt   time.Time `json:"approved_at"`
	RootHMAC     string    `json:"root_hmac"` // HMAC of trust root used for approval
}

// Sentinel errors.
var (
	ErrSelfApproval             = errors.New("self-approval is not permitted")
	ErrAlreadyApproved          = errors.New("member has already approved this request")
	ErrApprovalRequired         = errors.New("operation requires approval")
	ErrApprovalExpired          = errors.New("approval request has expired")
	ErrHardwarePresenceRequired = errors.New("hardware presence proof required to approve")
)

// Create creates a new approval request.
func Create(_ context.Context, capability, connection string, requester team.Member, mode ApprovalMode, n, m int) (*ApprovalRequest, error) {
	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("approval: generate id: %w", err)
	}

	// Validate N-of-M.
	if mode == ModeNofM && (n <= 0 || m <= 0 || n > m) {
		return nil, fmt.Errorf("approval: invalid N=%d, M=%d for NofM mode", n, m)
	}
	if mode == ModeTwoPerson {
		n = 2
		m = 2
	}

	return &ApprovalRequest{
		ID:            id,
		Capability:    capability,
		Connection:    connection,
		RequesterHMAC: requester.HMAC,
		Mode:          mode,
		N:             n,
		M:             m,
		Approvals:     []ApprovalEntry{},
		Status:        StatusPending,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(1 * time.Hour),
	}, nil
}

// Approve records an approval from approver (with hardware PresenceProof).
// Returns ErrSelfApproval if approver == requester.
// Transitions Status to Approved when quorum reached.
func Approve(_ context.Context, req *ApprovalRequest, approver team.Member, proof trust.PresenceProof) error {
	// Check expiry.
	if time.Now().After(req.ExpiresAt) {
		req.Status = StatusExpired
		return ErrApprovalExpired
	}

	// self-approval is blocked.
	if approver.HMAC == req.RequesterHMAC {
		return ErrSelfApproval
	}

	// C-9: hardware presence proof is required — zero-value proof is rejected.
	if proof.ConfirmedAt.IsZero() {
		return ErrHardwarePresenceRequired
	}

	// Check if already approved by this member.
	for _, a := range req.Approvals {
		if a.ApproverHMAC == approver.HMAC {
			return ErrAlreadyApproved
		}
	}

	entry := ApprovalEntry{
		ApproverHMAC: approver.HMAC,
		ApprovedAt:   time.Now().UTC(),
		RootHMAC:     proof.RootID, // already HMACd
	}
	req.Approvals = append(req.Approvals, entry)

	// Check quorum.
	if len(req.Approvals) >= req.N {
		req.Status = StatusApproved
	}
	return nil
}

// Check returns ErrApprovalRequired if req does not have quorum.
func Check(req *ApprovalRequest) error {
	if req.Status == StatusApproved {
		return nil
	}
	if req.Status == StatusExpired || time.Now().After(req.ExpiresAt) {
		return ErrApprovalExpired
	}
	return ErrApprovalRequired
}

// MintJWTClaim returns the approval claim for gateway JWT when approved.
// Returns a value-free claim (all member IDs are HMACd).
func MintJWTClaim(req *ApprovalRequest) map[string]interface{} {
	approvers := make([]string, 0, len(req.Approvals))
	for _, a := range req.Approvals {
		approvers = append(approvers, a.ApproverHMAC) // already HMACd
	}
	return map[string]interface{}{
		"approval_id":         req.ID,
		"capability":          req.Capability,
		"connection":          req.Connection,
		"requester_hmac":      req.RequesterHMAC,
		"mode":                string(req.Mode),
		"approvers_hmac":      approvers,
		"two_person_approved": req.Status == StatusApproved && req.Mode == ModeTwoPerson,
		"approved_at":         time.Now().UTC().Format(time.RFC3339),
	}
}

// generateID generates a random 16-byte hex ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
