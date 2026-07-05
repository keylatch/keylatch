// Package inventory implements team resource inventory management.
package inventory

import (
	"context"
	"time"

	"github.com/keylatch/keylatch/internal/team"
)

// ItemType identifies the kind of inventory item.
type ItemType string

const (
	ItemConnection   ItemType = "connection"
	ItemSharedSecret ItemType = "shared_secret"
	ItemGrant        ItemType = "grant"
	ItemPolicy       ItemType = "policy"
)

// Item is a single inventory entry.
type Item struct {
	ID         string     `json:"id"`
	Type       ItemType   `json:"type"`
	OwnerHMAC  string     `json:"owner_hmac"` // HMAC of owner member ID
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Stale      bool       `json:"stale"`
}

// ListOpts controls which items are returned by List.
type ListOpts struct {
	Type      ItemType
	OwnerHMAC string
}

// List returns all inventory items for the team, filtered by opts.
// Currently returns items derived from team members and connections.
func List(_ context.Context, t *team.Team, opts ListOpts) ([]Item, error) {
	var items []Item

	for _, m := range t.Members {
		if m.Status == team.MemberRemoved {
			continue
		}
		// Each active member has a grant item associated.
		item := Item{
			ID:        "grant-" + m.ID,
			Type:      ItemGrant,
			OwnerHMAC: m.HMAC,
			CreatedAt: m.JoinedAt,
		}
		if opts.Type != "" && item.Type != opts.Type {
			continue
		}
		if opts.OwnerHMAC != "" && item.OwnerHMAC != opts.OwnerHMAC {
			continue
		}
		items = append(items, item)
	}

	return items, nil
}

// Stale returns items that have not been accessed within the threshold.
func Stale(_ context.Context, t *team.Team, threshold time.Duration) ([]Item, error) {
	now := time.Now()
	var stale []Item

	for _, m := range t.Members {
		if m.Status == team.MemberRemoved {
			continue
		}
		item := Item{
			ID:        "grant-" + m.ID,
			Type:      ItemGrant,
			OwnerHMAC: m.HMAC,
			CreatedAt: m.JoinedAt,
		}
		// Check staleness.
		lastUsed := m.JoinedAt
		if now.Sub(lastUsed) > threshold {
			item.Stale = true
			stale = append(stale, item)
		}
	}

	return stale, nil
}
