package review_test

import (
	"context"
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

func TestRevokeUnused_NoError(t *testing.T) {
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
	if err := review.RevokeUnused(context.Background(), tt, 24*time.Hour); err != nil {
		t.Errorf("RevokeUnused: %v", err)
	}
}
