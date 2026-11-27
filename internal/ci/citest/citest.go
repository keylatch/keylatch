// Package citest serves a signing key set and issues tokens signed by it, for
// tests of code that verifies CI OIDC tokens.
package citest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeyID is the id of the signing key the issuer publishes.
const KeyID = "test-key"

// Issuer is a fake CI provider: a key set endpoint and a signer.
type Issuer struct {
	Key *rsa.PrivateKey
	// JWKSURL is where the key set is served (plain http).
	JWKSURL string
}

// NewIssuer starts the key set server and stops it when the test ends.
func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	doc, err := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "RSA", "kid": KeyID, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("encode key set: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	return &Issuer{Key: key, JWKSURL: srv.URL}
}

// Sign returns a token carrying claims, signed with RS256 under KeyID.
func (i *Issuer) Sign(t testing.TB, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = KeyID
	s, err := tok.SignedString(i.Key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// GitHubClaims are the claims of a valid GitHub Actions token for the
// repository and ref, with the audience, expiring in an hour.
func GitHubClaims(audience, repository, ref string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": "https://token.actions.githubusercontent.com", "sub": "repo:" + repository + ":ref:" + ref,
		"aud": audience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"repository": repository, "ref": ref, "environment": "prod",
		"job_workflow_ref": repository + "/.github/workflows/deploy.yml@" + ref,
	}
}
