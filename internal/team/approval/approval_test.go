package approval_test

import (
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/approval"
	"github.com/keylatch/keylatch/internal/trust"
)

func newMember(id string) team.Member {
	return team.Member{
		ID:     id,
		HMAC:   "hmac-" + id,
		Role:   team.RoleDeveloper,
		Status: team.MemberActive,
	}
}

func newProof() trust.PresenceProof {
	return trust.PresenceProof{
		Method:      "fido2",
		ConfirmedAt: time.Now(),
		RootID:      "hmac-root-id",
	}
}

func TestTwoPerson_QuorumFlow(t *testing.T) {
	ctx := context.Background()
	requester := newMember("alice")
	approver1 := newMember("bob")
	approver2 := newMember("carol")

	req, err := approval.Create(ctx, "read", "conn-1", requester, approval.ModeTwoPerson, 2, 2)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Single approval leaves Pending.
	if err := approval.Approve(ctx, req, approver1, newProof()); err != nil {
		t.Fatalf("Approve (1st): %v", err)
	}
	if req.Status != approval.StatusPending {
		t.Errorf("Status after 1 approval = %v, want Pending", req.Status)
	}

	// Second approval from different member → Approved.
	if err := approval.Approve(ctx, req, approver2, newProof()); err != nil {
		t.Fatalf("Approve (2nd): %v", err)
	}
	if req.Status != approval.StatusApproved {
		t.Errorf("Status after 2 approvals = %v, want Approved", req.Status)
	}
}

func TestSelfApproval_Blocked(t *testing.T) {
	ctx := context.Background()
	requester := newMember("alice")

	req, err := approval.Create(ctx, "write", "conn-1", requester, approval.ModeTwoPerson, 2, 2)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// self-approval must be blocked.
	err = approval.Approve(ctx, req, requester, newProof())
	if err != approval.ErrSelfApproval {
		t.Errorf("self-approval: got %v, want ErrSelfApproval", err)
	}
}

func TestApprove_ExpiredRequest(t *testing.T) {
	ctx := context.Background()
	requester := newMember("alice")
	approver := newMember("bob")

	req, err := approval.Create(ctx, "read", "conn-1", requester, approval.ModeTwoPerson, 2, 2)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Force expiry.
	req.ExpiresAt = time.Now().Add(-time.Minute)

	err = approval.Approve(ctx, req, approver, newProof())
	if err != approval.ErrApprovalExpired {
		t.Errorf("expired request: got %v, want ErrApprovalExpired", err)
	}
}

func TestNofM_Quorum(t *testing.T) {
	ctx := context.Background()
	requester := newMember("alice")

	req, err := approval.Create(ctx, "write", "conn-1", requester, approval.ModeNofM, 2, 5)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	members := []team.Member{newMember("bob"), newMember("carol"), newMember("dave")}

	// n-1 approvals should leave Pending.
	if err := approval.Approve(ctx, req, members[0], newProof()); err != nil {
		t.Fatalf("Approve (1): %v", err)
	}
	if req.Status != approval.StatusPending {
		t.Errorf("Status after 1 of 2 = %v, want Pending", req.Status)
	}

	// n approvals → Approved.
	if err := approval.Approve(ctx, req, members[1], newProof()); err != nil {
		t.Fatalf("Approve (2): %v", err)
	}
	if req.Status != approval.StatusApproved {
		t.Errorf("Status after 2 of 2 = %v, want Approved", req.Status)
	}
}

func TestMintJWTClaim_ValueFree(t *testing.T) {
	ctx := context.Background()
	requester := newMember("alice")
	approver := newMember("bob")

	req, err := approval.Create(ctx, "read", "conn-1", requester, approval.ModeTwoPerson, 2, 2)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = approval.Approve(ctx, req, approver, newProof())
	_ = approval.Approve(ctx, req, newMember("carol"), newProof())

	claim := approval.MintJWTClaim(req)

	// Verify no raw emails appear.
	for k, v := range claim {
		str, ok := v.(string)
		if !ok {
			continue
		}
		if contains(str, "alice@") || contains(str, "bob@") {
			t.Errorf("claim[%s] = %q contains raw email — value-free invariant violated", k, str)
		}
	}

	// Verify two_person_approved is true.
	if tpa, ok := claim["two_person_approved"].(bool); !ok || !tpa {
		t.Errorf("two_person_approved = %v, want true", claim["two_person_approved"])
	}
}

func TestApprove_ZeroProof_Rejected(t *testing.T) {
	ctx := context.Background()
	requester := newMember("alice")
	approver := newMember("bob")

	req, err := approval.Create(ctx, "read", "conn-1", requester, approval.ModeTwoPerson, 2, 2)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// C-9: zero PresenceProof must be rejected.
	zeroProof := trust.PresenceProof{} // zero-value: ConfirmedAt.IsZero() == true
	err = approval.Approve(ctx, req, approver, zeroProof)
	if err != approval.ErrHardwarePresenceRequired {
		t.Errorf("zero proof: got %v, want ErrHardwarePresenceRequired", err)
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
