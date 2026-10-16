// Package ci verifies the OIDC token a CI job presents and matches it against
// the operator's trust configuration.
//
// A token is accepted only when its signature checks against the issuer's key
// set, it carries the audience the trust entry names, and its repository, ref
// (with its kind), environment and workflow claims match. Every failure to
// fetch keys or to match a claim denies.
package ci

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keylatch/keylatch/internal/config"
)

// Providers Keylatch can verify tokens from.
const (
	GitHubActions = "github-actions"
	GitLab        = "gitlab"
)

// Errors returned for a token that must not be accepted.
var (
	ErrTrustInvalid  = errors.New("ci: trust entry is incomplete or unsafe")
	ErrToken         = errors.New("ci: token is not valid")
	ErrKeys          = errors.New("ci: issuer keys are unavailable")
	ErrRepository    = errors.New("ci: repository is not trusted")
	ErrRef           = errors.New("ci: ref is not trusted")
	ErrEnvironment   = errors.New("ci: environment is not trusted")
	ErrWorkflow      = errors.New("ci: job workflow is not trusted")
	ErrNoTrustMatch  = errors.New("ci: no trust entry accepts this token")
	errUnknownKeyID  = errors.New("ci: token key is not in the issuer's key set")
	signingMethods   = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
	maxJWKSBytes     = int64(1 << 20)
	jwksCacheTTL     = 5 * time.Minute
	jwksFetchTimeout = 10 * time.Second
	clockLeeway      = 30 * time.Second
)

type providerSpec struct {
	issuer        string
	jwksPath      string
	repoClaim     string
	environment   string
	workflowClaim string
}

var specs = map[string]providerSpec{
	GitHubActions: {
		issuer: "https://token.actions.githubusercontent.com", jwksPath: "/.well-known/jwks",
		repoClaim: "repository", environment: "environment", workflowClaim: "job_workflow_ref",
	},
	GitLab: {
		issuer: "https://gitlab.com", jwksPath: "/oauth/discovery/keys",
		repoClaim: "project_path", environment: "environment", workflowClaim: "ci_config_ref_uri",
	},
}

// Identity is what a verified token proves.
type Identity struct {
	Provider    string
	Subject     string
	Repository  string
	Ref         string
	Environment string
	Workflow    string
	Audience    string
	Expiry      time.Time
}

// Validate rejects a trust entry that would accept more than intended: a
// missing audience, repository or ref list, a bare branch name instead of a
// full ref, or a key set URL that is not https.
func Validate(t config.CITrust) error { return validate(t, false) }

func validate(t config.CITrust, allowHTTP bool) error {
	spec, ok := specs[t.Provider]
	if !ok {
		return fmt.Errorf("%w: provider %q (use %s or %s)", ErrTrustInvalid, t.Provider, GitHubActions, GitLab)
	}
	if strings.TrimSpace(t.Audience) == "" {
		return fmt.Errorf("%w: audience is required", ErrTrustInvalid)
	}
	if len(t.Repositories) == 0 || slices.Contains(t.Repositories, "") || slices.Contains(t.Repositories, "*") {
		return fmt.Errorf("%w: repositories must name at least one repository", ErrTrustInvalid)
	}
	if len(t.Refs) == 0 {
		return fmt.Errorf("%w: refs must name at least one ref", ErrTrustInvalid)
	}
	for _, r := range t.Refs {
		if !strings.HasPrefix(r, "refs/heads/") && !strings.HasPrefix(r, "refs/tags/") {
			return fmt.Errorf("%w: ref %q must start with refs/heads/ or refs/tags/", ErrTrustInvalid, r)
		}
	}
	if len(t.Connections) == 0 {
		return fmt.Errorf("%w: connections must list at least one connection", ErrTrustInvalid)
	}
	if t.MaxTTL < 0 || t.MaxTTL > 3600 {
		return fmt.Errorf("%w: max_ttl must be 1-3600 seconds", ErrTrustInvalid)
	}
	for _, raw := range []string{issuerOf(t, spec), jwksURL(t, spec)} {
		if u, err := url.Parse(raw); err != nil || u.Host == "" || (u.Scheme != "https" && !(allowHTTP && u.Scheme == "http")) {
			return fmt.Errorf("%w: %q must be an https URL", ErrTrustInvalid, raw)
		}
	}
	return nil
}

func issuerOf(t config.CITrust, spec providerSpec) string {
	if t.Issuer != "" {
		return strings.TrimRight(t.Issuer, "/")
	}
	return spec.issuer
}

func jwksURL(t config.CITrust, spec providerSpec) string {
	if t.JWKSURL != "" {
		return t.JWKSURL
	}
	return issuerOf(t, spec) + spec.jwksPath
}

// Verifier checks tokens and caches issuer key sets.
type Verifier struct {
	// HTTP fetches key sets; a default client with a timeout when nil.
	HTTP *http.Client
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// AllowHTTP accepts key sets served over http. Tests only.
	AllowHTTP bool

	mu    sync.Mutex
	cache map[string]keySet
}

type keySet struct {
	keys    map[string]crypto.PublicKey
	fetched time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks raw against t and returns the identity it proves.
func (v *Verifier) Verify(ctx context.Context, raw string, t config.CITrust) (Identity, error) {
	if err := validate(t, v.AllowHTTP); err != nil {
		return Identity{}, err
	}
	spec := specs[t.Provider]
	keyURL := jwksURL(t, spec)
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(signingMethods),
		jwt.WithIssuer(issuerOf(t, spec)),
		jwt.WithAudience(t.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockLeeway),
		jwt.WithTimeFunc(v.now),
	)
	tok, err := parser.ParseWithClaims(raw, claims, func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		return v.key(ctx, keyURL, kid)
	})
	switch {
	case errors.Is(err, ErrKeys):
		return Identity{}, ErrKeys
	case err != nil:
		return Identity{}, fmt.Errorf("%w: %v", ErrToken, err)
	case !tok.Valid:
		return Identity{}, ErrToken
	}

	id := Identity{Provider: t.Provider, Audience: t.Audience}
	id.Subject, _ = claims["sub"].(string)
	id.Repository, _ = claims[spec.repoClaim].(string)
	id.Environment, _ = claims[spec.environment].(string)
	id.Workflow, _ = claims[spec.workflowClaim].(string)
	id.Ref = fullRef(t.Provider, claims)
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		id.Expiry = exp.Time
	}

	if !matchAny(t.Repositories, id.Repository) {
		return Identity{}, ErrRepository
	}
	if !matchAny(t.Refs, id.Ref) {
		return Identity{}, ErrRef
	}
	if len(t.Environments) > 0 && !matchAny(t.Environments, id.Environment) {
		return Identity{}, ErrEnvironment
	}
	if len(t.JobWorkflowRefs) > 0 && !matchAny(t.JobWorkflowRefs, id.Workflow) {
		return Identity{}, ErrWorkflow
	}
	return id, nil
}

// VerifyAny returns the first trust entry for the provider that accepts raw,
// with the identity it proves. The error of the last entry tried is returned
// when none does.
func (v *Verifier) VerifyAny(ctx context.Context, raw string, trust []config.CITrust, provider, audience string) (config.CITrust, Identity, error) {
	err := ErrNoTrustMatch
	for _, t := range trust {
		if t.Provider != provider || (audience != "" && t.Audience != audience) {
			continue
		}
		id, verr := v.Verify(ctx, raw, t)
		if verr == nil {
			return t, id, nil
		}
		err = verr
	}
	return config.CITrust{}, Identity{}, err
}

// fullRef returns the token's ref spelled with its kind, so a tag named main
// never equals the branch main. GitLab reports the short name and ref_type.
func fullRef(provider string, claims jwt.MapClaims) string {
	ref, _ := claims["ref"].(string)
	if provider != GitLab || ref == "" {
		return ref
	}
	switch kind, _ := claims["ref_type"].(string); kind {
	case "branch":
		return "refs/heads/" + ref
	case "tag":
		return "refs/tags/" + ref
	}
	return ""
}

// matchAny reports whether value equals a pattern or matches it with "*"
// standing for one path segment. An empty value never matches.
func matchAny(patterns []string, value string) bool {
	if value == "" {
		return false
	}
	return slices.ContainsFunc(patterns, func(p string) bool {
		if p == value {
			return true
		}
		ok, err := path.Match(p, value)
		return err == nil && ok
	})
}

func (v *Verifier) key(ctx context.Context, keyURL, kid string) (crypto.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("ci: token has no key id")
	}
	v.mu.Lock()
	set, cached := v.cache[keyURL]
	v.mu.Unlock()
	fresh := cached && v.now().Sub(set.fetched) < jwksCacheTTL
	if fresh {
		if k, ok := set.keys[kid]; ok {
			return k, nil
		}
	}
	// A key id the cache lacks may be a rotation: refetch once, but not more
	// often than the cache lifetime allows for an id the issuer never serves.
	if fresh && v.now().Sub(set.fetched) < time.Minute {
		return nil, errUnknownKeyID
	}
	keys, err := v.fetch(ctx, keyURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeys, err)
	}
	v.mu.Lock()
	if v.cache == nil {
		v.cache = map[string]keySet{}
	}
	v.cache[keyURL] = keySet{keys: keys, fetched: v.now()}
	v.mu.Unlock()
	k, ok := keys[kid]
	if !ok {
		return nil, errUnknownKeyID
	}
	return k, nil
}

func (v *Verifier) fetch(ctx context.Context, keyURL string) (map[string]crypto.PublicKey, error) {
	if u, err := url.Parse(keyURL); err != nil || (u.Scheme != "https" && !(v.AllowHTTP && u.Scheme == "http")) {
		return nil, fmt.Errorf("key set URL %q is not https", keyURL)
	}
	client := v.HTTP
	if client == nil {
		client = &http.Client{Timeout: jwksFetchTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("key set request returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if pub, err := k.public(); err == nil {
			keys[k.Kid] = pub
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("key set has no usable signing key")
	}
	return keys, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) public() (crypto.PublicKey, error) {
	dec := base64.RawURLEncoding.DecodeString
	switch k.Kty {
	case "RSA":
		n, err := dec(k.N)
		if err != nil {
			return nil, err
		}
		e, err := dec(k.E)
		if err != nil {
			return nil, err
		}
		exp := new(big.Int).SetBytes(e)
		if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 {
			return nil, errors.New("unsupported RSA exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("RSA key shorter than 2048 bits")
		}
		return pub, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		size := (curve.Params().BitSize + 7) / 8
		x, err := coordinate(k.X, size)
		if err != nil {
			return nil, err
		}
		y, err := coordinate(k.Y, size)
		if err != nil {
			return nil, err
		}
		return ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// coordinate decodes a JWK coordinate and left-pads it to size bytes; some
// issuers strip leading zeros despite RFC 7518 section 6.2.1.2.
func coordinate(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > size {
		return nil, fmt.Errorf("coordinate is %d bytes, curve allows %d", len(b), size)
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out, nil
}
