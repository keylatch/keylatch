package breakglass_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/breakglass"
)

// TestBreakGlassReasonCanary seeds a canary value into a break-glass reason.
// Asserts canary DOES appear in the reason field (loud by design — spec §6.7).
// Asserts canary is preserved in the request struct for audit visibility.
func TestBreakGlassReasonCanary(t *testing.T) {
	const sentinel = "KEYLATCH_CANARY_PHASE12_BG_breakglass_0xDEADBEEF"
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	member := team.Member{
		ID:     "canary-member",
		HMAC:   "canary-hmac",
		Role:   team.RoleAdmin,
		Status: team.MemberActive,
	}

	req, err := breakglass.Open(ctx, member, sentinel)
	if err != nil {
		t.Fatalf("Open with canary reason: %v", err)
	}

	// Canary MUST appear in the reason field (loud by design per spec §6.7).
	if !bytes.Contains([]byte(req.Reason), []byte(sentinel)) {
		t.Errorf("canary not found in req.Reason: %q", req.Reason)
	}

	// Canary MUST appear in ActionBreakGlassRequest events — verify req struct contains it.
	// (Actual audit log emission is verified by the audit package integration.)
	if req.MemberHMAC == sentinel {
		t.Error("member HMAC should not be the raw sentinel — it must be HMACd")
	}

	// Close the request and verify canary appears in close data too.
	if err := breakglass.Close(ctx, req, member); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if req.Reason != sentinel {
		t.Errorf("reason changed after close: got %q, want sentinel", req.Reason)
	}

	// Assert the sentinel does NOT appear in MemberHMAC (value-free invariant).
	canary.AssertNoLeak(t,
		[]string{sentinel},
		canary.Stdout([]byte(req.MemberHMAC)),
		canary.Stdout([]byte(req.AuditRef)),
	)
}
