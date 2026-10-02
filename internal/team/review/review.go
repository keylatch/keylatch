// Package review implements access review workflows.
package review

import (
	"context"
	"fmt"
	"strings"
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

// RevokeUnused reports grants and shared secrets that have been stale >
// threshold and could not actually be revoked.
//
// M9a: this used to silently no-op ("In production: revoke the grant or
// shared secret" + `_ = item`) and always return nil, which is worse than
// doing nothing — a caller checking the error would believe stale access
// had been cleaned up when nothing happened. Neither item type is
// genuinely revocable from here today, for two unrelated reasons, so this
// now fails loudly instead of pretending:
//
//   - ItemGrant: inventory.Stale synthesizes a "grant-<memberID>" ID for
//     every stale team member — it does not read internal/grant's real
//     store, and grants are created independently via `keylatch grant
//     create` with no structural link to team membership. internal/grant
//     DOES have a working, idempotent Revoke(ctx, path, id) primitive, but
//     there is no real grant ID available here to pass it — calling
//     Revoke with the synthetic ID would just fail "not found" every
//     time, which is a different flavor of the same lie.
//   - ItemSharedSecret: internal/team/sharedsecret has no revoke/delete
//     primitive, and no persistence/store layer at all — only in-memory
//     Create/Read/Rotate/Rewrap on an already-loaded value. Adding one
//     is a real feature (store design), not a wiring fix.
//
// Also note: no production code calls RevokeUnused or Review today —
// `keylatch team review` is not a registered CLI command (verified via
// repo-wide grep of internal/cli/team_cmd.go's AddCommand calls: list,
// invite, remove, transfer, role, rotate-owner-key, hash-email — no
// review). Wiring a CLI entry point and a real team-member↔grant link is
// tracked separately.
func RevokeUnused(ctx context.Context, t *team.Team, threshold time.Duration) error {
	staleItems, err := inventory.Stale(ctx, t, threshold)
	if err != nil {
		return fmt.Errorf("review: get stale items: %w", err)
	}

	var unrevoked []string
	for _, item := range staleItems {
		switch item.Type {
		case inventory.ItemGrant:
			unrevoked = append(unrevoked, fmt.Sprintf(
				"%s (grant: inventory has no real grant ID to revoke — not wired to internal/grant)", item.ID))
		case inventory.ItemSharedSecret:
			unrevoked = append(unrevoked, fmt.Sprintf(
				"%s (shared_secret: no revoke primitive exists)", item.ID))
		}
	}
	if len(unrevoked) > 0 {
		return fmt.Errorf("review: %d stale item(s) could not be revoked (not implemented): %s",
			len(unrevoked), strings.Join(unrevoked, "; "))
	}
	return nil
}
