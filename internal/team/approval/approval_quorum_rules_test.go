package approval_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team/approval"
	"github.com/keylatch/keylatch/internal/trust"
)

func TestCreate_RejectsInvalidNofM(t *testing.T) {
	requester := newMember("alice")
	for _, nm := range [][2]int{{0, 3}, {-1, 3}, {2, 0}, {4, 3}} {
		_, err := approval.Create(context.Background(), "write", "c", requester, approval.ModeNofM, nm[0], nm[1])
		if err == nil {
			t.Errorf("N=%d M=%d accepted", nm[0], nm[1])
		}
	}
}

func TestCreate_TwoPersonForcesTwoOfTwo(t *testing.T) {
	req, err := approval.Create(context.Background(), "write", "c", newMember("alice"), approval.ModeTwoPerson, 1, 9)
	if err != nil {
		t.Fatal(err)
	}
	if req.N != 2 || req.M != 2 {
		t.Fatalf("N=%d M=%d, want 2/2", req.N, req.M)
	}
	if req.RequesterHMAC != "hmac-alice" || req.Status != approval.StatusPending {
		t.Fatalf("unexpected request: %+v", req)
	}
	if ttl := req.ExpiresAt.Sub(req.CreatedAt); ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Fatalf("ttl = %v, want ~1h", ttl)
	}
}

func TestApprove_RequiresHardwarePresence(t *testing.T) {
	req, err := approval.Create(context.Background(), "write", "c", newMember("alice"), approval.ModeTwoPerson, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	err = approval.Approve(context.Background(), req, newMember("bob"), trust.PresenceProof{Method: "fido2", RootID: "r"})
	if !errors.Is(err, approval.ErrHardwarePresenceRequired) {
		t.Fatalf("want ErrHardwarePresenceRequired, got %v", err)
	}
	if len(req.Approvals) != 0 {
		t.Fatal("approval recorded without presence proof")
	}
}

func TestApprove_ExpiryMarksRequestExpired(t *testing.T) {
	req, err := approval.Create(context.Background(), "write", "c", newMember("alice"), approval.ModeTwoPerson, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	req.ExpiresAt = time.Now().Add(-time.Second)
	if err := approval.Approve(context.Background(), req, newMember("bob"), newProof()); !errors.Is(err, approval.ErrApprovalExpired) {
		t.Fatalf("want ErrApprovalExpired, got %v", err)
	}
	if req.Status != approval.StatusExpired {
		t.Fatalf("status = %s, want expired", req.Status)
	}
	if err := approval.Check(req); !errors.Is(err, approval.ErrApprovalExpired) {
		t.Fatalf("Check: want ErrApprovalExpired, got %v", err)
	}
}

func TestCheck_Decisions(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	cases := []struct {
		name    string
		status  approval.ApprovalStatus
		expires time.Time
		want    error
	}{
		{"approved", approval.StatusApproved, future, nil},
		{"pending", approval.StatusPending, future, approval.ErrApprovalRequired},
		{"denied", approval.StatusDenied, future, approval.ErrApprovalRequired},
		{"expired status", approval.StatusExpired, future, approval.ErrApprovalExpired},
		{"pending past expiry", approval.StatusPending, past, approval.ErrApprovalExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := approval.Check(&approval.ApprovalRequest{Status: tc.status, ExpiresAt: tc.expires})
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMintJWTClaim_TwoPersonOnlyWhenApproved(t *testing.T) {
	ctx := context.Background()
	req, err := approval.Create(ctx, "write", "conn-9", newMember("alice"), approval.ModeTwoPerson, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.Approve(ctx, req, newMember("bob"), newProof()); err != nil {
		t.Fatal(err)
	}
	claim := approval.MintJWTClaim(req)
	if claim["two_person_approved"] != false {
		t.Fatal("single approval must not yield two_person_approved")
	}
	if err := approval.Approve(ctx, req, newMember("carol"), newProof()); err != nil {
		t.Fatal(err)
	}
	claim = approval.MintJWTClaim(req)
	if claim["two_person_approved"] != true {
		t.Fatal("two approvals should yield two_person_approved")
	}
	approvers, ok := claim["approvers_hmac"].([]string)
	if !ok || len(approvers) != 2 || approvers[0] != "hmac-bob" || approvers[1] != "hmac-carol" {
		t.Fatalf("approvers_hmac = %v", claim["approvers_hmac"])
	}
	if claim["requester_hmac"] != "hmac-alice" || claim["connection"] != "conn-9" || claim["approval_id"] != req.ID {
		t.Fatalf("claim = %v", claim)
	}

	nofm, err := approval.Create(ctx, "write", "c", newMember("alice"), approval.ModeNofM, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.Approve(ctx, nofm, newMember("bob"), newProof()); err != nil {
		t.Fatal(err)
	}
	if nofm.Status != approval.StatusApproved {
		t.Fatal("1-of-3 should be approved after one approval")
	}
	if approval.MintJWTClaim(nofm)["two_person_approved"] != false {
		t.Fatal("n_of_m approval must not claim two-person")
	}
}
