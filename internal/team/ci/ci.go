// Package ci implements CI/CD OIDC identity verification.
//
// Security invariants:
// - Strict verification of aud, iss, repo, and branch claims.
// - JWKS fail-closed: expired cache + unreachable endpoint → ErrJWKSUnavailable.
package ci

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CIProvider identifies the CI/CD system.
type CIProvider string

const (
	ProviderGitHubActions CIProvider = "github-actions"
	ProviderGitLabCI      CIProvider = "gitlab-ci"
	ProviderCircleCI      CIProvider = "circleci"
	ProviderBuildkite     CIProvider = "buildkite"
)

// Identity holds the verified CI/CD identity from a OIDC token.
type Identity struct {
	Provider CIProvider
	Subject  string
	Repo     string
	Branch   string
	Workflow string
	Job      string
	Env      string
	Issuer   string
	Audience []string
	Expiry   time.Time
}

// VerifyOpts controls how a CI OIDC JWT is verified.
type VerifyOpts struct {
	Provider        CIProvider
	Audience        []string // required audience values
	AllowedRepos    []string // glob patterns
	AllowedBranches []string // glob patterns
}

// Sentinel errors.
var (
	ErrCIAudMissing       = errors.New("CI OIDC token missing required audience claim")
	ErrCIIssuerMismatch   = errors.New("CI OIDC token issuer does not match expected")
	ErrCIRepoDenied       = errors.New("CI OIDC token repo not in allowlist")
	ErrCIBranchDenied     = errors.New("CI OIDC token branch not in allowlist")
	ErrJWKSUnavailable    = errors.New("JWKS endpoint unavailable — fail closed")
	ErrTokenInvalid       = errors.New("CI OIDC token is invalid or tampered")
	ErrTokenExpired       = errors.New("CI OIDC token has expired")
	ErrCISignatureInvalid = errors.New("CI OIDC token signature invalid")
)

// providerConfig holds OIDC configuration for a CI provider.
type providerConfig struct {
	Issuer        string
	JWKSEndpoint  string
	RepoClaim     string
	BranchClaim   string
	WorkflowClaim string
	JobClaim      string
}

// providers maps CIProvider to its OIDC configuration.
var providers = map[CIProvider]providerConfig{
	ProviderGitHubActions: {
		Issuer:        "https://token.actions.githubusercontent.com",
		JWKSEndpoint:  "https://token.actions.githubusercontent.com/.well-known/jwks",
		RepoClaim:     "repository",
		BranchClaim:   "ref",
		WorkflowClaim: "workflow",
		JobClaim:      "job_workflow_ref",
	},
	ProviderGitLabCI: {
		Issuer:        "https://gitlab.com",
		JWKSEndpoint:  "https://gitlab.com/-/jwks",
		RepoClaim:     "project_path",
		BranchClaim:   "ref",
		WorkflowClaim: "pipeline_source",
		JobClaim:      "job_id",
	},
	ProviderCircleCI: {
		Issuer:        "https://oidc.circleci.com/org",
		JWKSEndpoint:  "https://oidc.circleci.com/.well-known/jwks",
		RepoClaim:     "oidc.circleci.com/project-id",
		BranchClaim:   "oidc.circleci.com/context-ids",
		WorkflowClaim: "oidc.circleci.com/workflow-ids",
		JobClaim:      "oidc.circleci.com/job-id",
	},
	ProviderBuildkite: {
		Issuer:        "https://agent.buildkite.com",
		JWKSEndpoint:  "https://agent.buildkite.com/.well-known/jwks",
		RepoClaim:     "pipeline_slug",
		BranchClaim:   "branch",
		WorkflowClaim: "pipeline_slug",
		JobClaim:      "job_id",
	},
}

// jwtHeader is the decoded JWT header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwtClaims holds the standard and provider-specific JWT claims.
//
//nolint:unused // planned: typed claim extraction replaces map[string]interface{}
type jwtClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience audience `json:"aud"`
	Expiry   int64    `json:"exp"`
	// Provider-specific claims (populated from provider config).
	Extra map[string]interface{} `json:"-"`
}

// audience handles both string and []string aud values in JWT.
//
//nolint:unused // planned: used by jwtClaims.Audience in typed claim extraction
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error { //nolint:unused // planned: used by jwtClaims
	// Try string first.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = audience{s}
		return nil
	}
	// Try []string.
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return err
	}
	*a = audience(ss)
	return nil
}

// PublicKey wraps a crypto.PublicKey with its key ID and algorithm.
type PublicKey struct {
	KeyID     string
	Algorithm string
	Key       crypto.PublicKey
}

// jwksCache holds the cached JWKS keys for a provider.
type jwksCache struct {
	keys      []PublicKey
	fetchedAt time.Time
	ttl       time.Duration
}

// isStale returns true if the cache entry is older than its TTL.
func (c *jwksCache) isStale(now time.Time) bool {
	return now.Sub(c.fetchedAt) > c.ttl
}

const defaultJWKSTTL = 5 * time.Minute

// jwksCacheMu guards jwksCacheMap.
var (
	jwksCacheMu  sync.RWMutex
	jwksCacheMap = make(map[CIProvider]jwksCache)
)

// jwksOverrideURL allows tests to override the JWKS endpoint per provider.
// Key: provider, Value: URL to use instead of the configured endpoint.
var jwksOverrideURL = make(map[CIProvider]string)

// jwksHTTPClient is the HTTP client used to fetch JWKS. Tests may replace it.
var jwksHTTPClient = &http.Client{Timeout: 10 * time.Second}

// getJWKS returns public keys for the provider, fetching from network if cache is stale.
// Fail-closed: stale cache + unreachable endpoint → ErrJWKSUnavailable.
func getJWKS(ctx context.Context, provider CIProvider, endpoint string) ([]PublicKey, error) {
	now := time.Now()

	// Check cache under read lock.
	jwksCacheMu.RLock()
	entry, ok := jwksCacheMap[provider]
	jwksCacheMu.RUnlock()

	if ok && !entry.isStale(now) {
		return entry.keys, nil
	}

	// Cache is stale or missing — fetch from endpoint.
	url := endpoint
	if override, has := jwksOverrideURL[provider]; has {
		url = override
	}

	keys, err := fetchJWKS(ctx, url)
	if err != nil {
		// fail-closed — return ErrJWKSUnavailable even on stale cache hit.
		return nil, ErrJWKSUnavailable
	}

	// Update cache under write lock.
	jwksCacheMu.Lock()
	jwksCacheMap[provider] = jwksCache{
		keys:      keys,
		fetchedAt: now,
		ttl:       defaultJWKSTTL,
	}
	jwksCacheMu.Unlock()

	return keys, nil
}

// rawJWK is the JSON representation of a single JWK key.
type rawJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA fields.
	N string `json:"n"`
	E string `json:"e"`
	// EC fields.
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// rawJWKS is the JSON representation of a JWKS document.
type rawJWKS struct {
	Keys []rawJWK `json:"keys"`
}

// fetchJWKS fetches and parses the JWKS from the given URL.
func fetchJWKS(ctx context.Context, url string) ([]PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("ci: create JWKS request: %w", err)
	}
	resp, err := jwksHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ci: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ci: JWKS endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("ci: read JWKS response: %w", err)
	}
	var jwks rawJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("ci: parse JWKS: %w", err)
	}
	return parseJWKSKeys(jwks.Keys)
}

// parseJWKSKeys parses a slice of rawJWK into PublicKey values.
func parseJWKSKeys(rawKeys []rawJWK) ([]PublicKey, error) {
	var keys []PublicKey
	for _, rk := range rawKeys {
		pk, err := parseJWK(rk)
		if err != nil {
			// Skip unparseable keys rather than failing entirely.
			continue
		}
		keys = append(keys, pk)
	}
	return keys, nil
}

// parseJWK parses a single JWK into a PublicKey.
func parseJWK(rk rawJWK) (PublicKey, error) {
	switch rk.Kty {
	case "RSA":
		return parseRSAJWK(rk)
	case "EC":
		return parseECJWK(rk)
	default:
		return PublicKey{}, fmt.Errorf("ci: unsupported JWK kty %q", rk.Kty)
	}
}

// base64URLDecodeBigInt decodes a base64url-encoded big integer.
func base64URLDecodeBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// parseRSAJWK parses an RSA JWK.
func parseRSAJWK(rk rawJWK) (PublicKey, error) {
	if rk.N == "" || rk.E == "" {
		return PublicKey{}, errors.New("ci: RSA JWK missing n or e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(rk.N)
	if err != nil {
		return PublicKey{}, fmt.Errorf("ci: decode RSA n: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	eBytes, err := base64.RawURLEncoding.DecodeString(rk.E)
	if err != nil {
		return PublicKey{}, fmt.Errorf("ci: decode RSA e: %w", err)
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return PublicKey{}, errors.New("ci: RSA exponent too large")
	}
	pub := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}
	alg := rk.Alg
	if alg == "" {
		alg = "RS256"
	}
	return PublicKey{KeyID: rk.Kid, Algorithm: alg, Key: pub}, nil
}

// parseECJWK parses an EC JWK.
func parseECJWK(rk rawJWK) (PublicKey, error) {
	if rk.X == "" || rk.Y == "" {
		return PublicKey{}, errors.New("ci: EC JWK missing x or y")
	}
	var curve elliptic.Curve
	switch rk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return PublicKey{}, fmt.Errorf("ci: unsupported EC curve %q", rk.Crv)
	}
	xInt, err := base64URLDecodeBigInt(rk.X)
	if err != nil {
		return PublicKey{}, fmt.Errorf("ci: decode EC x: %w", err)
	}
	yInt, err := base64URLDecodeBigInt(rk.Y)
	if err != nil {
		return PublicKey{}, fmt.Errorf("ci: decode EC y: %w", err)
	}
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     xInt,
		Y:     yInt,
	}
	alg := rk.Alg
	if alg == "" {
		alg = "ES256"
	}
	return PublicKey{KeyID: rk.Kid, Algorithm: alg, Key: pub}, nil
}

// verifyJWTSignature verifies the JWT signature against the given set of public keys.
// Supports RS256, RS384, RS512, ES256, ES384, ES512.
func verifyJWTSignature(rawJWT string, header *jwtHeader, keys []PublicKey) error {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return ErrTokenInvalid
	}
	sigInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrTokenInvalid
	}

	// Try all keys; prefer matching kid.
	var tried int
	for _, pk := range keys {
		if header.Kid != "" && pk.KeyID != "" && pk.KeyID != header.Kid {
			continue
		}
		tried++
		if err := verifyWithKey(sigInput, sig, header.Alg, pk); err == nil {
			return nil
		}
	}
	if tried == 0 {
		// No key matched kid — try all keys.
		for _, pk := range keys {
			tried++
			if err := verifyWithKey(sigInput, sig, header.Alg, pk); err == nil {
				return nil
			}
		}
	}
	return ErrCISignatureInvalid
}

// verifyWithKey verifies a JWT signature with a single public key.
func verifyWithKey(sigInput string, sig []byte, alg string, pk PublicKey) error {
	switch pk.Key.(type) {
	case *rsa.PublicKey:
		return verifyRSA(sigInput, sig, alg, pk.Key.(*rsa.PublicKey))
	case *ecdsa.PublicKey:
		return verifyEC(sigInput, sig, alg, pk.Key.(*ecdsa.PublicKey))
	default:
		return fmt.Errorf("ci: unsupported key type")
	}
}

// verifyRSA verifies an RSA signature (RS256/RS384/RS512).
func verifyRSA(sigInput string, sig []byte, alg string, pub *rsa.PublicKey) error {
	var hashAlg crypto.Hash
	switch alg {
	case "RS256":
		hashAlg = crypto.SHA256
	case "RS384":
		hashAlg = crypto.SHA384
	case "RS512":
		hashAlg = crypto.SHA512
	default:
		// Try RS256 by default.
		hashAlg = crypto.SHA256
	}
	var digest []byte
	switch hashAlg {
	case crypto.SHA256:
		h := sha256.Sum256([]byte(sigInput))
		digest = h[:]
	case crypto.SHA384:
		h := sha512.Sum384([]byte(sigInput))
		digest = h[:]
	case crypto.SHA512:
		h := sha512.Sum512([]byte(sigInput))
		digest = h[:]
	}
	return rsa.VerifyPKCS1v15(pub, hashAlg, digest, sig)
}

// verifyEC verifies an ECDSA signature (ES256/ES384/ES512).
func verifyEC(sigInput string, sig []byte, alg string, pub *ecdsa.PublicKey) error {
	var digest []byte
	switch alg {
	case "ES256":
		h := sha256.Sum256([]byte(sigInput))
		digest = h[:]
	case "ES384":
		h := sha512.Sum384([]byte(sigInput))
		digest = h[:]
	case "ES512":
		h := sha512.Sum512([]byte(sigInput))
		digest = h[:]
	default:
		h := sha256.Sum256([]byte(sigInput))
		digest = h[:]
	}
	// ECDSA JWT signatures are encoded as fixed-width R||S (per RFC 7518).
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keySize {
		return ErrCISignatureInvalid
	}
	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])
	if !ecdsa.Verify(pub, digest, r, s) {
		return ErrCISignatureInvalid
	}
	return nil
}

// parseJWT parses a JWT and returns header, claims, error.
// Does NOT verify signature.
func parseJWT(rawJWT string) (*jwtHeader, map[string]interface{}, error) {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil, nil, ErrTokenInvalid
	}

	// Decode header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, ErrTokenInvalid
	}

	// Decode claims.
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, ErrTokenInvalid
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, ErrTokenInvalid
	}

	return &header, claims, nil
}

// Verify verifies a CI OIDC JWT.
// JWKS fail-closed: expired cache + unreachable → ErrJWKSUnavailable.
// Strict aud/iss/repo/branch verification.
func Verify(ctx context.Context, rawJWT string, opts VerifyOpts) (Identity, error) {
	cfg, ok := providers[opts.Provider]
	if !ok {
		return Identity{}, fmt.Errorf("ci: unknown provider %q", opts.Provider)
	}

	// Parse JWT structure.
	header, claims, err := parseJWT(rawJWT)
	if err != nil {
		return Identity{}, ErrTokenInvalid
	}

	// Fetch JWKS and verify signature.
	keys, err := getJWKS(ctx, opts.Provider, cfg.JWKSEndpoint)
	if err != nil {
		return Identity{}, err // ErrJWKSUnavailable
	}
	if err := verifyJWTSignature(rawJWT, header, keys); err != nil {
		return Identity{}, err // ErrCISignatureInvalid
	}

	// Verify issuer — exact equality, no prefix matching.
	iss, _ := claims["iss"].(string)
	if iss != cfg.Issuer {
		return Identity{}, ErrCIIssuerMismatch
	}

	// C-4: exp claim is required.
	exp, ok := claims["exp"].(float64)
	if !ok {
		return Identity{}, fmt.Errorf("CI OIDC token missing required exp claim")
	}
	if time.Now().Unix() > int64(exp) {
		return Identity{}, ErrTokenExpired
	}

	// Verify audience.
	if len(opts.Audience) > 0 {
		audClaim := extractAudience(claims["aud"])
		if !hasAnyAud(audClaim, opts.Audience) {
			return Identity{}, ErrCIAudMissing
		}
	}

	// Extract repo claim.
	repo, _ := claims[cfg.RepoClaim].(string)

	// C-3: empty repo bypasses allowlist — deny if repo is empty and allowlist is set.
	if len(opts.AllowedRepos) > 0 {
		if repo == "" || !matchAny(opts.AllowedRepos, repo) {
			return Identity{}, ErrCIRepoDenied
		}
	}

	// Extract branch claim.
	branch, _ := claims[cfg.BranchClaim].(string)
	// Normalize branch ref (github uses "refs/heads/main").
	branch = normalizeBranch(branch)

	// C-3: empty branch bypasses allowlist — deny if branch is empty and allowlist is set.
	if len(opts.AllowedBranches) > 0 {
		if branch == "" || !matchAny(opts.AllowedBranches, branch) {
			return Identity{}, ErrCIBranchDenied
		}
	}

	// Build identity.
	sub, _ := claims["sub"].(string)
	workflow, _ := claims[cfg.WorkflowClaim].(string)
	job, _ := claims[cfg.JobClaim].(string)

	expiry := time.Unix(int64(exp), 0)

	return Identity{
		Provider: opts.Provider,
		Subject:  sub,
		Repo:     repo,
		Branch:   branch,
		Workflow: workflow,
		Job:      job,
		Issuer:   iss,
		Audience: extractAudience(claims["aud"]),
		Expiry:   expiry,
	}, nil
}

// extractAudience extracts audience values from a claim (string or []interface{}).
func extractAudience(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, a := range t {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// hasAnyAud returns true if any of the required audiences are present.
func hasAnyAud(tokenAud []string, required []string) bool {
	for _, req := range required {
		for _, got := range tokenAud {
			if got == req {
				return true
			}
		}
	}
	return false
}

// matchAny returns true if value matches any of the glob patterns.
func matchAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, value)
		if err == nil && matched {
			return true
		}
		// Also support substring matching for common patterns.
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(value, prefix+"/") || value == prefix {
				return true
			}
		}
	}
	return false
}

// normalizeBranch strips refs/heads/ prefix for comparison.
func normalizeBranch(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")
	return ref
}

// --- Test helpers ---

// TestJWKS holds a test RSA key pair for JWT verification tests.
type TestJWKS struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyID      string
}

// NewTestJWKS generates a new test JWKS key pair.
func NewTestJWKS() (*TestJWKS, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid := generateKID()
	return &TestJWKS{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		KeyID:      kid,
	}, nil
}

func generateKID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// MintTestJWT mints a test JWT signed with the given RSA private key.
// If privKey is nil, mints an unsigned stub (for structural tests only).
func MintTestJWT(claims map[string]interface{}) (string, error) {
	return MintSignedTestJWT(claims, nil, "")
}

// MintSignedTestJWT mints a JWT signed with privKey (RS256).
// If privKey is nil, falls back to an unsigned stub with a fake signature.
func MintSignedTestJWT(claims map[string]interface{}, privKey *rsa.PrivateKey, kid string) (string, error) {
	alg := "RS256"
	if privKey == nil {
		alg = "HS256"
	}
	header := map[string]interface{}{
		"alg": alg,
		"typ": "JWT",
	}
	if kid != "" {
		header["kid"] = kid
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sigInput := headerB64 + "." + claimsB64

	var sig []byte
	if privKey != nil {
		h := sha256.Sum256([]byte(sigInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h[:])
		if err != nil {
			return "", fmt.Errorf("MintSignedTestJWT: sign: %w", err)
		}
	} else {
		// Unsigned stub — use SHA-256 of input as fake signature.
		h := sha256.Sum256([]byte(sigInput + "/keylatch-test"))
		sig = h[:]
	}

	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ServeTestJWKS returns the JWKS JSON for a TestJWKS key.
func (j *TestJWKS) ServeTestJWKS() []byte {
	// Build RSA JWK.
	nB64 := base64.RawURLEncoding.EncodeToString(j.PublicKey.N.Bytes())
	eBytes := big.NewInt(int64(j.PublicKey.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)
	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": j.KeyID,
		"alg": "RS256",
		"use": "sig",
		"n":   nB64,
		"e":   eB64,
	}
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	b, _ := json.Marshal(jwks)
	return b
}

// SetJWKSOverride replaces the JWKS endpoint for a provider in tests.
// Call this before Verify. Clear with ClearJWKSOverride after the test.
func SetJWKSOverride(provider CIProvider, url string) {
	jwksCacheMu.Lock()
	defer jwksCacheMu.Unlock()
	jwksOverrideURL[provider] = url
	// Clear cache for provider to force re-fetch from override URL.
	delete(jwksCacheMap, provider)
}

// ClearJWKSOverride removes the JWKS URL override for a provider.
func ClearJWKSOverride(provider CIProvider) {
	jwksCacheMu.Lock()
	defer jwksCacheMu.Unlock()
	delete(jwksOverrideURL, provider)
	delete(jwksCacheMap, provider)
}
