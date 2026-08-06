package review_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/inventory"
	"github.com/keylatch/keylatch/internal/team/review"
)

func TestReview_StaleItem_Revoke(t *testing.T) {
	items := []inventory.Item{
		{ID: "item-1", Type: inventory.ItemGrant, OwnerHMAC: "hmac-1", Stale: true, CreatedAt: time.Now().Add(-48 * time.Hour)},
	}
	tt := &team.Team{ID: "team-test"}

	results, err := review.Review(context.Background(), tt, items)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "revoke" {
		t.Errorf("stale item action = %q, want revoke", results[0].Action)
	}
}

func TestReview_SharedSecret_Rotate(t *testing.T) {
	items := []inventory.Item{
		{ID: "secret-1", Type: inventory.ItemSharedSecret, OwnerHMAC: "hmac-1", Stale: false, CreatedAt: time.Now()},
	}
	tt := &team.Team{ID: "team-test"}

	results, err := review.Review(context.Background(), tt, items)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Action != "rotate" {
		t.Errorf("shared secret action = %q, want rotate", results[0].Action)
	}
}

// TestRevokeUnused_StaleGrant_ReturnsExplicitError verifies that a stale
// grant-type item produces an explicit error naming the item (M9a) instead
// of the previous silent-no-op "success" — reaching this call site with a
// clean nil result used to falsely imply the grant had actually been
// revoked.
func TestRevokeUnused_StaleGrant_ReturnsExplicitError(t *testing.T) {
	tt := &team.Team{
		ID:   "team-test",
		Name: "Test",
		Members: []team.Member{
			{
				ID:       "m1",
				HMAC:     "h1",
				Role:     team.RoleDeveloper,
				JoinedAt: time.Now().Add(-48 * time.Hour),
				Status:   team.MemberActive,
			},
		},
	}
	err := review.RevokeUnused(context.Background(), tt, 24*time.Hour)
	if err == nil {
		t.Fatal("expected an explicit error for an unrevoked stale grant, got nil")
	}
	if !strings.Contains(err.Error(), "grant-m1") {
		t.Errorf("error should name the unrevoked item ID, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("error should say revocation is not implemented, got %q", err.Error())
	}
}

// TestRevokeUnused_NoStaleItems_NoError verifies that when nothing is
// stale, RevokeUnused returns nil — the honest-failure behavior above only
// fires when there is actually something it could not revoke. Calling it
// twice with the same input is idempotent (both calls return the same nil
// result; no side effects are performed either way today).
func TestRevokeUnused_NoStaleItems_NoError(t *testing.T) {
	tt := &team.Team{
		ID:   "team-test",
		Name: "Test",
		Members: []team.Member{
			{
				ID:       "m1",
				HMAC:     "h1",
				Role:     team.RoleDeveloper,
				JoinedAt: time.Now(),
				Status:   team.MemberActive,
			},
		},
	}
	for i := 0; i < 2; i++ {
		if err := review.RevokeUnused(context.Background(), tt, 24*time.Hour); err != nil {
			t.Errorf("call %d: RevokeUnused: %v", i, err)
		}
	}
}

// TestRevokeUnused_RemovedMember_NotStale verifies removed members are
// excluded from the stale set (inventory.Stale already skips
// team.MemberRemoved), so RevokeUnused has nothing to report for them.
func TestRevokeUnused_RemovedMember_NotStale(t *testing.T) {
	tt := &team.Team{
		ID:   "team-test",
		Name: "Test",
		Members: []team.Member{
			{
				ID:       "m1",
				HMAC:     "h1",
				Role:     team.RoleDeveloper,
				JoinedAt: time.Now().Add(-48 * time.Hour),
				Status:   team.MemberRemoved,
			},
		},
	}
	if err := review.RevokeUnused(context.Background(), tt, 24*time.Hour); err != nil {
		t.Errorf("RevokeUnused: %v", err)
	}
}
