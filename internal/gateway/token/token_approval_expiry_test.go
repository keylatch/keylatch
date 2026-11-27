package token

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signWithApprovalClaim(t *testing.T, key []byte, id, apvExp string) string {
	t.Helper()
	claims := gatewayClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Actor:          "actor",
		Caps:           []string{"cap"},
		ApprovalExpiry: apvExp,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func mintPlain(t *testing.T, key []byte, store, parent string) (string, *Token) {
	t.Helper()
	s, tok, err := Mint(TokenSpec{Actor: "actor", Capabilities: []string{"cap"}, TTL: time.Hour, Parent: parent, SigningKey: key, StorePath: store})
	if err != nil {
		t.Fatal(err)
	}
	return s, tok
}

func TestVerify_RejectsExpiredApprovalClaim(t *testing.T) {
	key := make([]byte, 32)
	store := filepath.Join(t.TempDir(), "tokens.json")
	_, tok := mintPlain(t, key, store, "")

	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := Verify(signWithApprovalClaim(t, key, tok.ID, past), nil, key, store); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerify_RejectsUnparsableApprovalClaim(t *testing.T) {
	key := make([]byte, 32)
	store := filepath.Join(t.TempDir(), "tokens.json")
	_, tok := mintPlain(t, key, store, "")

	if _, err := Verify(signWithApprovalClaim(t, key, tok.ID, "not-a-time"), nil, key, store); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerify_AcceptsFutureApprovalExpiry(t *testing.T) {
	key := make([]byte, 32)
	store := filepath.Join(t.TempDir(), "tokens.json")
	s, tok := mintPlain(t, key, store, "")

	future := time.Now().Add(time.Hour)
	tokens, err := readTokens(store)
	if err != nil {
		t.Fatal(err)
	}
	for i := range tokens {
		if tokens[i].ID == tok.ID {
			tokens[i].ApprovalExpiry = &future
			sealRecord(key, &tokens[i])
		}
	}
	if err = writeTokens(store, tokens); err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(s, nil, key, store); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err = Verify(signWithApprovalClaim(t, key, tok.ID, future.UTC().Format(time.RFC3339)), nil, key, store); err != nil {
		t.Fatalf("Verify with future claim: %v", err)
	}
}

func TestRevoke_CascadesThroughAllLevels(t *testing.T) {
	key := make([]byte, 32)
	store := filepath.Join(t.TempDir(), "tokens.json")

	_, root := mintPlain(t, key, store, "")
	var jwts []string
	parent := root.ID
	for i := 0; i < 3; i++ {
		s, tok := mintPlain(t, key, store, parent)
		jwts = append(jwts, s)
		parent = tok.ID
	}
	if err := Revoke(root.ID, store, key); err != nil {
		t.Fatal(err)
	}
	for i, s := range jwts {
		if _, err := Verify(s, nil, key, store); !errors.Is(err, ErrTokenRevoked) {
			t.Errorf("descendant %d: expected ErrTokenRevoked, got %v", i+1, err)
		}
	}
}
