package token

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// A record edited in place (here: an approval expiry in the past) is not
// accepted, because the edit invalidates the record's MAC.
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

// Revoking a token revokes every descendant, not only its direct children.
func TestSecurityRegression_RevokeDescendants(t *testing.T) {
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
	if e = Revoke(parent.ID, d, key); e != nil {
		t.Fatal(e)
	}
	if _, e = Verify(jwt, httptest.NewRequest("GET", "/", nil), key, d); e == nil {
		t.Fatal("grandchild token remains valid after root revocation")
	}
}
