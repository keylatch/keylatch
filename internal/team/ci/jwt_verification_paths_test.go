package ci

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mxSigner struct {
	kid string
	alg string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func (s mxSigner) jwk() map[string]any {
	if s.rsa != nil {
		return map[string]any{
			"kty": "RSA", "kid": s.kid, "alg": s.alg,
			"n": base64.RawURLEncoding.EncodeToString(s.rsa.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.rsa.E)).Bytes()),
		}
	}
	size := (s.ec.Curve.Params().BitSize + 7) / 8
	crv := map[int]string{256: "P-256", 384: "P-384", 521: "P-521"}[s.ec.Curve.Params().BitSize]
	return map[string]any{
		"kty": "EC", "kid": s.kid, "crv": crv,
		"x": base64.RawURLEncoding.EncodeToString(s.ec.X.FillBytes(make([]byte, size))),
		"y": base64.RawURLEncoding.EncodeToString(s.ec.Y.FillBytes(make([]byte, size))),
	}
}

func mxDigest(alg, input string) (crypto.Hash, []byte) {
	switch alg[2:] {
	case "384":
		h := sha512.Sum384([]byte(input))
		return crypto.SHA384, h[:]
	case "512":
		h := sha512.Sum512([]byte(input))
		return crypto.SHA512, h[:]
	}
	h := sha256.Sum256([]byte(input))
	return crypto.SHA256, h[:]
}

func (s mxSigner) mint(t *testing.T, headerKid string, claims map[string]any) string {
	t.Helper()
	hdr, err := json.Marshal(map[string]any{"alg": s.alg, "kid": headerKid, "typ": "JWT"})
	require.NoError(t, err)
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	hash, digest := mxDigest(s.alg, input)
	var sig []byte
	if s.rsa != nil {
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsa, hash, digest)
		require.NoError(t, err)
	} else {
		r, ss, signErr := ecdsa.Sign(rand.Reader, s.ec, digest)
		require.NoError(t, signErr)
		size := (s.ec.Curve.Params().BitSize + 7) / 8
		sig = append(r.FillBytes(make([]byte, size)), ss.FillBytes(make([]byte, size))...)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func mxRSASigner(t *testing.T, kid, alg string) mxSigner {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return mxSigner{kid: kid, alg: alg, rsa: k}
}

func mxECSigner(t *testing.T, kid, alg string, curve elliptic.Curve) mxSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return mxSigner{kid: kid, alg: alg, ec: k}
}

// mxJWKS serves the given signers' public keys (plus junk entries that must
// be skipped) and points the provider at it for the test.
func mxJWKS(t *testing.T, provider CIProvider, signers ...mxSigner) *int32 {
	t.Helper()
	keys := []any{
		map[string]any{"kty": "oct", "kid": "sym"},
		map[string]any{"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"},
	}
	for _, s := range signers {
		keys = append(keys, s.jwk())
	}
	doc, err := json.Marshal(map[string]any{"keys": keys})
	require.NoError(t, err)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(doc)
	}))
	t.Cleanup(srv.Close)
	SetJWKSOverride(provider, srv.URL)
	t.Cleanup(func() { ClearJWKSOverride(provider) })
	return &hits
}

func mxGitHubClaims(extra map[string]any) map[string]any {
	c := map[string]any{
		"iss":        "https://token.actions.githubusercontent.com",
		"sub":        "repo:acme/app:ref:refs/heads/main",
		"aud":        []any{"keylatch", 42},
		"exp":        time.Now().Add(time.Hour).Unix(),
		"repository": "acme/app",
		"ref":        "refs/heads/main",
		"workflow":   "deploy",
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestVerify_AllSupportedAlgorithms(t *testing.T) {
	signers := []mxSigner{
		mxRSASigner(t, "rs384", "RS384"),
		mxRSASigner(t, "rs512", "RS512"),
		mxECSigner(t, "es256", "ES256", elliptic.P256()),
		mxECSigner(t, "es384", "ES384", elliptic.P384()),
		mxECSigner(t, "es512", "ES512", elliptic.P521()),
	}
	mxJWKS(t, ProviderGitHubActions, signers...)
	opts := VerifyOpts{Provider: ProviderGitHubActions, Audience: []string{"keylatch"}, AllowedRepos: []string{"acme/*"}, AllowedBranches: []string{"main"}}
	for _, s := range signers {
		id, err := Verify(context.Background(), s.mint(t, s.kid, mxGitHubClaims(nil)), opts)
		require.NoError(t, err, s.alg)
		assert.Equal(t, "acme/app", id.Repo)
		assert.Equal(t, "main", id.Branch)
		assert.Equal(t, []string{"keylatch"}, id.Audience, "non-string audience entries are dropped")
		assert.Equal(t, "deploy", id.Workflow)
	}
}

func TestVerify_UnknownKidFallsBackToAllKeys(t *testing.T) {
	s := mxECSigner(t, "real", "ES256", elliptic.P256())
	mxJWKS(t, ProviderGitHubActions, s)
	_, err := Verify(context.Background(), s.mint(t, "rotated-away", mxGitHubClaims(nil)), VerifyOpts{Provider: ProviderGitHubActions})
	require.NoError(t, err)
}

func TestVerify_RejectsForgeries(t *testing.T) {
	trusted := mxECSigner(t, "k1", "ES256", elliptic.P256())
	attacker := mxECSigner(t, "k1", "ES256", elliptic.P256())
	mxJWKS(t, ProviderGitHubActions, trusted)
	opts := VerifyOpts{Provider: ProviderGitHubActions}

	_, err := Verify(context.Background(), attacker.mint(t, "k1", mxGitHubClaims(nil)), opts)
	assert.ErrorIs(t, err, ErrCISignatureInvalid, "same kid, different key")

	good := trusted.mint(t, "k1", mxGitHubClaims(nil))
	parts := splitJWT(good)
	truncated := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("short"))
	_, err = Verify(context.Background(), truncated, opts)
	assert.ErrorIs(t, err, ErrCISignatureInvalid)

	_, err = Verify(context.Background(), parts[0]+"."+parts[1]+".***", opts)
	assert.ErrorIs(t, err, ErrTokenInvalid)

	noneHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	_, err = Verify(context.Background(), noneHdr+"."+parts[1]+".", opts)
	assert.ErrorIs(t, err, ErrCISignatureInvalid, "alg none is never accepted")
}

func splitJWT(s string) [3]string {
	var out [3]string
	i := 0
	start := 0
	for j := 0; j < len(s); j++ {
		if s[j] == '.' {
			out[i] = s[start:j]
			i++
			start = j + 1
		}
	}
	out[i] = s[start:]
	return out
}

func TestVerify_MalformedTokens(t *testing.T) {
	_, err := Verify(context.Background(), "a.b.c", VerifyOpts{Provider: "jenkins"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")

	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, tok := range map[string]string{
		"two parts":         "a.b",
		"header not base64": "***." + b64("{}") + ".x",
		"header not json":   b64("nope") + "." + b64("{}") + ".x",
		"claims not base64": b64("{}") + ".***.x",
		"claims not json":   b64("{}") + "." + b64("nope") + ".x",
	} {
		_, err := Verify(context.Background(), tok, VerifyOpts{Provider: ProviderGitHubActions})
		assert.ErrorIs(t, err, ErrTokenInvalid, name)
	}
}

func TestGetJWKS_CachesAndFailsClosed(t *testing.T) {
	s := mxRSASigner(t, "k", "RS256")
	hits := mxJWKS(t, ProviderGitLabCI, s)
	ctx := context.Background()

	keys, err := getJWKS(ctx, ProviderGitLabCI, "unused")
	require.NoError(t, err)
	assert.Len(t, keys, 1, "unsupported and malformed JWKs are skipped")
	_, err = getJWKS(ctx, ProviderGitLabCI, "unused")
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(hits), "second call is served from cache")

	// Expire the cache and make the endpoint unreachable: must fail closed.
	jwksCacheMu.Lock()
	entry := jwksCacheMap[ProviderGitLabCI]
	entry.fetchedAt = time.Now().Add(-time.Hour)
	jwksCacheMap[ProviderGitLabCI] = entry
	jwksOverrideURL[ProviderGitLabCI] = "http://127.0.0.1:1/jwks"
	jwksCacheMu.Unlock()
	assert.True(t, entry.isStale(time.Now()))
	_, err = getJWKS(ctx, ProviderGitLabCI, "unused")
	assert.ErrorIs(t, err, ErrJWKSUnavailable)
}

func TestFetchJWKS_Errors(t *testing.T) {
	ctx := context.Background()
	_, err := fetchJWKS(ctx, "http://bad\x7fhost/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create JWKS request")

	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer status.Close()
	_, err = fetchJWKS(ctx, status.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 502")

	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer garbage.Close()
	_, err = fetchJWKS(ctx, garbage.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse JWKS")
}

func TestParseRSAJWK_Rejects(t *testing.T) {
	_, err := parseJWK(rawJWK{Kty: "RSA"})
	assert.Error(t, err)
	_, err = parseJWK(rawJWK{Kty: "RSA", N: "AQAB", E: "!!"})
	assert.Error(t, err)
	huge := base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 15)...))
	_, err = parseJWK(rawJWK{Kty: "RSA", N: "AQAB", E: huge})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exponent too large")

	pk, err := parseJWK(rawJWK{Kty: "RSA", N: "AQAB", E: "AQAB"})
	require.NoError(t, err)
	assert.Equal(t, "RS256", pk.Algorithm, "RSA keys default to RS256")
}

func TestVerifyWithKey_UnsupportedKeyType(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	err = verifyWithKey("x.y", []byte("sig"), "EdDSA", PublicKey{Key: pub})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestAudienceUnmarshal(t *testing.T) {
	var a audience
	require.NoError(t, json.Unmarshal([]byte(`"one"`), &a))
	assert.Equal(t, audience{"one"}, a)
	require.NoError(t, json.Unmarshal([]byte(`["a","b"]`), &a))
	assert.Equal(t, audience{"a", "b"}, a)
	assert.Error(t, json.Unmarshal([]byte(`42`), &a))
}

func TestClaimHelpers(t *testing.T) {
	assert.Nil(t, extractAudience(42))
	assert.Equal(t, []string{"x"}, extractAudience("x"))
	assert.True(t, matchAny([]string{"acme/*"}, "acme"), "a bare org matches its /* pattern")
	assert.True(t, matchAny([]string{"acme/*"}, "acme/deep/repo"))
	assert.False(t, matchAny([]string{"acme/*"}, "acme-evil/repo"))
	assert.False(t, matchAny([]string{"["}, "["), "malformed patterns never match")
	assert.Equal(t, "v1.2.3", normalizeBranch("refs/tags/v1.2.3"))
	assert.False(t, hasAnyAud([]string{"a"}, []string{"b"}))
}
