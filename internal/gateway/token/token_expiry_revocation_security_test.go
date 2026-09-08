package token

import (
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// TestSecurityRegression_F34_MintRejectsHardwareApprovalClaim verifies the
// narrow, closed part of F34: Mint refuses to produce an M1 gateway token
// from a spec carrying a hardware approval claim (ApprovalRootID plus an
// expiry), regardless of whether that expiry is already past.
func TestSecurityRegression_F34_MintRejectsHardwareApprovalClaim(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	d := filepath.Join(t.TempDir(), "tokens.json")
	key := make([]byte, 32)
	_, _, e := Mint(TokenSpec{Actor: "audit", Capabilities: []string{"test.write"}, TTL: time.Hour, ApprovalRootID: "root", ApprovalExpiry: &past, StorePath: d, SigningKey: key})
	if !errors.Is(e, ErrHardwareApprovalUnsupported) {
		t.Fatalf("expected ErrHardwareApprovalUnsupported, got %v", e)
	}
}

// KNOWN-FAILING (F34): the remaining, unresolved slice — Verify only checks
// the JWT's own expiry, never a persisted Token's ApprovalExpiry field. Mint
// can no longer produce such a record (see
// TestSecurityRegression_F34_MintRejectsHardwareApprovalClaim above), so this
// writes the store record directly to prove Verify still has no expiry check
// for any retained approval field — required before any future minting path
// is allowed to set one.
func TestSecurityRegression_F34_VerifyIgnoresStoredApprovalExpiry(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	d := filepath.Join(t.TempDir(), "tokens.json")
	key := make([]byte, 32)

	jwt, tok, e := Mint(TokenSpec{Actor: "audit", Capabilities: []string{"test.write"}, TTL: time.Hour, StorePath: d, SigningKey: key})
	if e != nil {
		t.Fatal(e)
	}

	tokens, e := readTokens(d)
	if e != nil {
		t.Fatal(e)
	}
	for i := range tokens {
		if tokens[i].ID == tok.ID {
			tokens[i].ApprovalExpiry = &past
		}
	}
	if e = writeTokens(d, tokens); e != nil {
		t.Fatal(e)
	}

	if _, e = Verify(jwt, httptest.NewRequest("GET", "/", nil), key, d); e == nil {
		t.Fatal("valid JWT accepted despite a persisted approval expiry an hour in the past")
	}
}

// KNOWN-FAILING (F35): Revoke only invalidates the immediate child of a
// token, so a grandchild token stays valid after the root token is revoked.
func TestSecurityRegression_F35_RevokeDescendants(t *testing.T) {
	d := filepath.Join(t.TempDir(), "tokens.json")
	key := make([]byte, 32)
	spec := TokenSpec{Actor: "audit", Capabilities: []string{"test.write"}, TTL: time.Hour, StorePath: d, SigningKey: key}
	_, parent, e := Mint(spec)
	if e != nil {
		t.Fatal(e)
	}
	spec.Parent = parent.ID
	_, child, e := Mint(spec)
	if e != nil {
		t.Fatal(e)
	}
	spec.Parent = child.ID
	jwt, _, e := Mint(spec)
	if e != nil {
		t.Fatal(e)
	}
	if e = Revoke(parent.ID, d); e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(jwt, httptest.NewRequest("GET", "/", nil), key, d); e == nil {
		t.Fatal("grandchild token remains valid after root revocation")
	}
}
