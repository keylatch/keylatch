package inventory_test

import (
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/inventory"
)

func newTeamWithMembers() *team.Team {
	t := &team.Team{
		ID:   "team-test",
		Name: "Test",
		Members: []team.Member{
			{
				ID:       "member-1",
				HMAC:     "hmac-1",
				Role:     team.RoleOwner,
				JoinedAt: time.Now().Add(-48 * time.Hour),
				Status:   team.MemberActive,
			},
			{
				ID:       "member-2",
				HMAC:     "hmac-2",
				Role:     team.RoleDeveloper,
				JoinedAt: time.Now().Add(-1 * time.Hour),
				Status:   team.MemberActive,
			},
		},
	}
	return t
}

func TestList_ReturnsItems(t *testing.T) {
	tt := newTeamWithMembers()
	items, err := inventory.List(context.Background(), tt, inventory.ListOpts{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) == 0 {
		t.Error("expected at least 1 item, got 0")
	}
}

func TestList_FilterByOwner(t *testing.T) {
	tt := newTeamWithMembers()
	items, err := inventory.List(context.Background(), tt, inventory.ListOpts{OwnerHMAC: "hmac-1"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, item := range items {
		if item.OwnerHMAC != "hmac-1" {
			t.Errorf("item %q has OwnerHMAC=%q, want hmac-1", item.ID, item.OwnerHMAC)
		}
	}
}

func TestStale_ReturnsOldItems(t *testing.T) {
	tt := newTeamWithMembers()
	// member-1 joined 48h ago — stale if threshold is 24h.
	stale, err := inventory.Stale(context.Background(), tt, 24*time.Hour)
	if err != nil {
		t.Fatalf("Stale: %v", err)
	}
	found := false
	for _, item := range stale {
		if item.OwnerHMAC == "hmac-1" {
			found = true
		}
	}
	if !found {
		t.Error("expected member-1 (48h old) in stale list with 24h threshold")
	}
}
