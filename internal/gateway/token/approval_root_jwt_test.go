package token_test

import (
	"errors"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/token"
)

// TestMint_RejectsSingleApprovalRootClaim verifies that Mint rejects any
// TokenSpec carrying single-root hardware approval claim fields — there is
// no hardware attestation workflow, so no combination of these fields
// may ever produce a token.
func TestMint_RejectsSingleApprovalRootClaim(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	expiry := time.Now().UTC().Add(5 * time.Minute)

	_, _, err := token.Mint(token.TokenSpec{
		Actor:              "alice",
		Capabilities:       []string{"inject"},
		TTL:                30 * time.Minute,
		SigningKey:         key,
		StorePath:          storePath,
		ApprovalRootID:     "root-spec-abc123",
		ApprovalCapability: "inject",
		ApprovalMaxAgeSec:  300,
		ApprovalExpiry:     &expiry,
		ApprovalBinding:    "command",
		TwoPerson:          false,
	})
	if !errors.Is(err, token.ErrHardwareApprovalUnsupported) {
		t.Fatalf("expected ErrHardwareApprovalUnsupported, got %v", err)
	}
}

// TestMint_RejectsTwoPersonApprovalClaim verifies that Mint rejects a
// two-person approval spec the same way as a single-root claim.
func TestMint_RejectsTwoPersonApprovalClaim(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	expiry := time.Now().UTC().Add(10 * time.Minute)

	_, _, err := token.Mint(token.TokenSpec{
		Actor:              "admin",
		Capabilities:       []string{"delete"},
		TTL:                1 * time.Hour,
		SigningKey:         key,
		StorePath:          storePath,
		ApprovalRootID:     "root-primary",
		ApprovalCapability: "delete",
		ApprovalMaxAgeSec:  600,
		ApprovalExpiry:     &expiry,
		ApprovalBinding:    "full",
		TwoPerson:          true,
		ApprovalRootIDs:    []string{"root-primary", "root-secondary"},
	})
	if !errors.Is(err, token.ErrHardwareApprovalUnsupported) {
		t.Fatalf("expected ErrHardwareApprovalUnsupported, got %v", err)
	}
}

// TestMint_NoApprovalRoot verifies that tokens without approval roots
// have zero-value approval fields (backward compat).
func TestMint_NoApprovalRoot(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	_, tok, err := token.Mint(token.TokenSpec{
		Actor:        "bot",
		Capabilities: []string{"status"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if tok.ApprovalRootHMAC != "" {
		t.Errorf("expected empty ApprovalRootHMAC, got %q", tok.ApprovalRootHMAC)
	}
	if tok.TwoPerson {
		t.Error("expected TwoPerson=false for non-approval token")
	}
	if len(tok.ApprovalRootHMACs) != 0 {
		t.Errorf("expected empty ApprovalRootHMACs, got %v", tok.ApprovalRootHMACs)
	}
}
