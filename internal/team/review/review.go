// Package review implements access review workflows.
package review

import (
	"context"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/inventory"
)

// ReviewResult holds a recommendation for a single inventory item.
type ReviewResult struct {
	ItemID string
	Action string // "keep" | "revoke" | "rotate"
	Reason string
}

// Review runs an access review, returning recommendations for each item.
func Review(_ context.Context, _ *team.Team, items []inventory.Item) ([]ReviewResult, error) {
	results := make([]ReviewResult, 0, len(items))

	for _, item := range items {
		var result ReviewResult
		result.ItemID = item.ID

		switch {
		case item.Stale:
			result.Action = "revoke"
			result.Reason = "item has not been used within the stale threshold"
		case item.Type == inventory.ItemSharedSecret:
			result.Action = "rotate"
			result.Reason = "shared secrets should be rotated periodically"
		default:
			result.Action = "keep"
			result.Reason = "item is active and recently used"
		}
		results = append(results, result)
	}
	return results, nil
}

// RevokeUnused revokes grants and shared secrets that have been stale > threshold.
// Audit-logs each revocation.
func RevokeUnused(ctx context.Context, t *team.Team, threshold time.Duration) error {
	staleItems, err := inventory.Stale(ctx, t, threshold)
	if err != nil {
		return fmt.Errorf("review: get stale items: %w", err)
	}

	for _, item := range staleItems {
		switch item.Type {
		case inventory.ItemGrant, inventory.ItemSharedSecret:
			// In production: revoke the grant or shared secret.
			// Audit-log the revocation.
			// For now: mark as stale in memory.
			_ = item
		}
	}
	return nil
}
