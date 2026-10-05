package token

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestMint_RejectsHardwareApprovalClaim verifies that Mint refuses to produce
// a gateway token from a spec carrying a hardware approval claim
// (ApprovalRootID plus an expiry), whether or not that expiry is past.
func TestMint_RejectsHardwareApprovalClaim(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	d := filepath.Join(t.TempDir(), "tokens.json")
	key := make([]byte, 32)
	_, _, e := Mint(TokenSpec{Actor: "audit", Capabilities: []string{"test.write"}, TTL: time.Hour, ApprovalRootID: "root", ApprovalExpiry: &past, StorePath: d, SigningKey: key})
	if !errors.Is(e, ErrHardwareApprovalUnsupported) {
		t.Fatalf("expected ErrHardwareApprovalUnsupported, got %v", e)
	}
}
