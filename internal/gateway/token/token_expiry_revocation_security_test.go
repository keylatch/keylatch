//go:build securitysuite

package token

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// Verify must reject a token whose persisted approval expiry has passed.
func TestSecurityRegression_VerifyIgnoresStoredApprovalExpiry(t *testing.T) {
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

// Revoking a token must invalidate every descendant, even through an already-revoked middle token.
func TestSecurityRegression_RevokeDescendants(t *testing.T) {
	d := filepath.Join(t.TempDir(), "tokens.json")
	key := make([]byte, 32)
	spec := TokenSpec{Actor: "audit", Capabilities: []string{"test.write"}, TTL: time.Hour, StorePath: d, SigningKey: key}
	req := httptest.NewRequest("GET", "/", nil)

	_, parent, e := Mint(spec)
	if e != nil {
		t.Fatal(e)
	}
	otherJWT, _, e := Mint(spec)
	if e != nil {
		t.Fatal(e)
	}
	spec.Parent = parent.ID
	childJWT, child, e := Mint(spec)
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
	if _, e = Verify(childJWT, req, key, d); e == nil {
		t.Fatal("child token remains valid after root revocation")
	}
	if _, e = Verify(jwt, req, key, d); e == nil {
		t.Fatal("grandchild token remains valid after root revocation")
	}
	if _, e = Verify(otherJWT, req, key, d); e != nil {
		t.Fatalf("unrelated token rejected after revocation: %v", e)
	}
}

// A revoked middle token must not stop the cascade from reaching its own children.
func TestSecurityRegression_RevokeReachesPastRevokedMiddle(t *testing.T) {
	d := filepath.Join(t.TempDir(), "tokens.json")
	key := make([]byte, 32)
	spec := TokenSpec{Actor: "audit", Capabilities: []string{"test.write"}, TTL: time.Hour, StorePath: d, SigningKey: key}

	_, root, e := Mint(spec)
	if e != nil {
		t.Fatal(e)
	}
	spec.Parent = root.ID
	_, middle, e := Mint(spec)
	if e != nil {
		t.Fatal(e)
	}
	spec.Parent = middle.ID
	jwt, _, e := Mint(spec)
	if e != nil {
		t.Fatal(e)
	}
	if e = Revoke(middle.ID, d); e != nil {
		t.Fatal(e)
	}
	if e = Revoke(root.ID, d); e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(jwt, httptest.NewRequest("GET", "/", nil), key, d); e == nil {
		t.Fatal("grandchild token remains valid")
	}
}
