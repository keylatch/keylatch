package token_test

import (
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/token"
)

// TestMint_ApprovalRootClaims verifies that approval root fields are HMAC'd
// and persisted correctly (raw root IDs must never appear in JWT/Token).
func TestMint_ApprovalRootClaims(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	expiry := time.Now().UTC().Add(5 * time.Minute)

	_, tok, err := token.Mint(token.TokenSpec{
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
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Verify raw root ID is NOT stored.
	if tok.ApprovalRootHMAC == "" {
		t.Error("expected ApprovalRootHMAC to be set")
	}
	if tok.ApprovalRootHMAC == "root-spec-abc123" {
		t.Error("ApprovalRootHMAC must be HMAC'd, not the raw root ID")
	}
	if tok.ApprovalCapability != "inject" {
		t.Errorf("ApprovalCapability: got %q, want %q", tok.ApprovalCapability, "inject")
	}
	if tok.ApprovalMaxAgeSec != 300 {
		t.Errorf("ApprovalMaxAgeSec: got %d, want 300", tok.ApprovalMaxAgeSec)
	}
	if tok.ApprovalExpiry == nil {
		t.Error("expected ApprovalExpiry to be set")
	}
	if tok.ApprovalBinding != "command" {
		t.Errorf("ApprovalBinding: got %q, want %q", tok.ApprovalBinding, "command")
	}
	if tok.TwoPerson {
		t.Error("expected TwoPerson=false")
	}
}

// TestMint_TwoPersonApprovalClaims verifies that two-person approval root IDs
// are each HMAC'd and the TwoPerson flag is set.
func TestMint_TwoPersonApprovalClaims(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	expiry := time.Now().UTC().Add(10 * time.Minute)

	_, tok, err := token.Mint(token.TokenSpec{
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
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if !tok.TwoPerson {
		t.Error("expected TwoPerson=true")
	}
	if len(tok.ApprovalRootHMACs) != 2 {
		t.Errorf("ApprovalRootHMACs: got %d, want 2", len(tok.ApprovalRootHMACs))
	}
	// Raw IDs must NOT appear in the HMAC slice.
	for _, h := range tok.ApprovalRootHMACs {
		if h == "root-primary" || h == "root-secondary" {
			t.Errorf("ApprovalRootHMACs contains raw root ID: %q", h)
		}
	}
	// Both HMACs must be distinct.
	if len(tok.ApprovalRootHMACs) == 2 && tok.ApprovalRootHMACs[0] == tok.ApprovalRootHMACs[1] {
		t.Error("HMAC'd root IDs should be distinct when raw IDs differ")
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

// TestMint_ApprovalRoot_VerifyRoundTrip verifies that approval claims survive
// a full Mint → Verify round-trip.
func TestMint_ApprovalRoot_VerifyRoundTrip(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	expiry := time.Now().UTC().Add(5 * time.Minute)

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:              "carol",
		Capabilities:       []string{"inject"},
		TTL:                1 * time.Hour,
		SigningKey:         key,
		StorePath:          storePath,
		ApprovalRootID:     "root-carol-yubikey",
		ApprovalCapability: "inject",
		ApprovalMaxAgeSec:  300,
		ApprovalExpiry:     &expiry,
		ApprovalBinding:    "cwd",
		TwoPerson:          false,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Verify round-trip.
	verifiedTok, err := token.Verify(jwtStr, nil, key, storePath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if verifiedTok.ApprovalRootHMAC == "" {
		t.Error("expected ApprovalRootHMAC after Verify")
	}
	if verifiedTok.ApprovalCapability != "inject" {
		t.Errorf("ApprovalCapability: got %q after Verify, want %q", verifiedTok.ApprovalCapability, "inject")
	}
	if verifiedTok.ApprovalBinding != "cwd" {
		t.Errorf("ApprovalBinding: got %q after Verify, want %q", verifiedTok.ApprovalBinding, "cwd")
	}
	if verifiedTok.ApprovalMaxAgeSec != 300 {
		t.Errorf("ApprovalMaxAgeSec: got %d after Verify, want 300", verifiedTok.ApprovalMaxAgeSec)
	}
}
