package token

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// KNOWN-FAILING (F34): Verify only checks the JWT's own expiry, not
// ApprovalExpiry, so a token remains valid after the hardware approval it
// depends on has expired.
func TestSecurityRegression_F34_ExpiredApproval(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	d := filepath.Join(t.TempDir(), "tokens.json")
	key := make([]byte, 32)
	jwt, _, e := Mint(TokenSpec{Actor: "audit", Capabilities: []string{"test.write"}, TTL: time.Hour, ApprovalRootID: "root", ApprovalExpiry: &past, StorePath: d, SigningKey: key})
	if e != nil {
		return
	}
	if _, e = Verify(jwt, httptest.NewRequest("GET", "/", nil), key, d); e == nil {
		t.Fatal("valid JWT accepted despite hardware approval expiring an hour ago")
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
