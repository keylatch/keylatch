package strategies

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultGCPIAMCredentialsEndpoint is the IAM Service Account Credentials API root.
const DefaultGCPIAMCredentialsEndpoint = "https://iamcredentials.googleapis.com" //nolint:gosec // G101 false positive: an API root URL, not a credential

const gcpTokenInfoURL = "https://oauth2.googleapis.com/tokeninfo" //nolint:gosec // G101 false positive: an introspection endpoint, not a credential

// MaxGCPTokenLifetime is the longest lifetime MintScoped asks for.
const MaxGCPTokenLifetime = time.Hour

// ErrGCPScopeMismatch is returned when Google issued a token that outlives the
// requested lifetime. No token is returned with it.
var ErrGCPScopeMismatch = errors.New("gcp_impersonation: issued token does not match the requested scope")

// GCPScope bounds one impersonated access token.
type GCPScope struct {
	// Scopes are the OAuth scopes the token carries; at least one is required.
	Scopes []string
	// Lifetime defaults to and may not exceed MaxGCPTokenLifetime.
	Lifetime time.Duration
}

// GCPToken is one impersonated access token.
type GCPToken struct {
	AccessToken []byte
	ExpiresAt   time.Time
}

// Zero wipes the token.
func (t *GCPToken) Zero() { clear(t.AccessToken) }

// GCPImpersonationStrategy mints access tokens for a service account with the
// IAM Credentials generateAccessToken call, authenticated as a source
// identity that holds the token-creator role on that account.
type GCPImpersonationStrategy struct {
	serviceAccount string
	endpoint       string
	tokenInfoURL   string
	getSourceToken func(namespace string) ([]byte, error)
	httpClient     *http.Client
	now            func() time.Time
}

// GCPOption configures a GCPImpersonationStrategy.
type GCPOption func(*GCPImpersonationStrategy)

// WithGCPEndpoint points the strategy at another IAM Credentials API root.
func WithGCPEndpoint(endpoint string) GCPOption {
	return func(s *GCPImpersonationStrategy) { s.endpoint = strings.TrimRight(endpoint, "/") }
}

// WithGCPTokenInfoURL replaces Google's token introspection endpoint for tests.
func WithGCPTokenInfoURL(endpoint string) GCPOption {
	return func(s *GCPImpersonationStrategy) { s.tokenInfoURL = endpoint }
}

// NewGCPImpersonationStrategy creates the strategy for one service account
// (its email address).
func NewGCPImpersonationStrategy(serviceAccount string, getSourceToken func(namespace string) ([]byte, error), opts ...GCPOption) *GCPImpersonationStrategy {
	s := &GCPImpersonationStrategy{
		serviceAccount: serviceAccount,
		endpoint:       DefaultGCPIAMCredentialsEndpoint,
		tokenInfoURL:   gcpTokenInfoURL,
		getSourceToken: getSourceToken,
		httpClient:     credentialHTTPClient(nil),
		now:            time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Provider returns "gcp".
func (s *GCPImpersonationStrategy) Provider() string { return "gcp" }

// MintScoped requests a token limited to scope.Scopes for scope.Lifetime.
func (s *GCPImpersonationStrategy) MintScoped(ctx context.Context, namespace string, scope GCPScope) (GCPToken, error) {
	if len(scope.Scopes) == 0 {
		return GCPToken{}, errors.New("gcp_impersonation: at least one scope is required")
	}
	for _, value := range scope.Scopes {
		if value == "" || strings.ContainsAny(value, " \t\r\n") {
			return GCPToken{}, errors.New("gcp_impersonation: scopes must be nonempty tokens without whitespace")
		}
	}
	if scope.Lifetime == 0 {
		scope.Lifetime = MaxGCPTokenLifetime
	}
	if scope.Lifetime < time.Second || scope.Lifetime > MaxGCPTokenLifetime {
		return GCPToken{}, fmt.Errorf("gcp_impersonation: the lifetime must be between 1 second and %s", MaxGCPTokenLifetime)
	}
	source, err := s.getSourceToken(namespace)
	if err != nil {
		return GCPToken{}, fmt.Errorf("gcp_impersonation: get source token: %w", err)
	}
	defer clear(source)

	payload, err := json.Marshal(map[string]any{
		"scope":    scope.Scopes,
		"lifetime": fmt.Sprintf("%ds", int(scope.Lifetime.Seconds())),
	})
	if err != nil {
		return GCPToken{}, err
	}
	endpoint := s.endpoint + "/v1/projects/-/serviceAccounts/" + url.PathEscape(s.serviceAccount) + ":generateAccessToken"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return GCPToken{}, fmt.Errorf("gcp_impersonation: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+string(source))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return GCPToken{}, fmt.Errorf("gcp_impersonation: http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return GCPToken{}, fmt.Errorf("gcp_impersonation: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return GCPToken{}, fmt.Errorf("gcp_impersonation: server returned %d", resp.StatusCode)
	}
	var reply struct {
		AccessToken string `json:"accessToken"`
		ExpireTime  string `json:"expireTime"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return GCPToken{}, fmt.Errorf("gcp_impersonation: parse response: %w", err)
	}
	exp, err := time.Parse(time.RFC3339, reply.ExpireTime)
	if err != nil || reply.AccessToken == "" {
		return GCPToken{}, fmt.Errorf("%w: incomplete reply", ErrGCPScopeMismatch)
	}
	now := s.now()
	if !exp.After(now) || exp.After(now.Add(scope.Lifetime+stsClockSkew)) {
		return GCPToken{}, fmt.Errorf("%w: token expires at %s, outside the requested %s", ErrGCPScopeMismatch, exp.UTC().Format(time.RFC3339), scope.Lifetime)
	}
	if err := s.verifyScope(ctx, reply.AccessToken, scope); err != nil {
		return GCPToken{}, err
	}
	return GCPToken{AccessToken: []byte(reply.AccessToken), ExpiresAt: exp}, nil
}

func (s *GCPImpersonationStrategy) verifyScope(ctx context.Context, token string, scope GCPScope) error {
	u, err := url.Parse(s.tokenInfoURL)
	if err != nil {
		return fmt.Errorf("%w: invalid introspection endpoint", ErrGCPScopeMismatch)
	}
	q := u.Query()
	q.Set("access_token", token)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("%w: cannot build introspection request", ErrGCPScopeMismatch)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: token introspection unavailable", ErrGCPScopeMismatch)
	}
	defer func() { _ = resp.Body.Close() }()
	var reply struct {
		Scope string `json:"scope"`
		Exp   string `json:"exp"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&reply) != nil {
		return fmt.Errorf("%w: invalid introspection response", ErrGCPScopeMismatch)
	}
	granted := strings.Fields(reply.Scope)
	if !subset(granted, scope.Scopes) || !subset(scope.Scopes, granted) {
		return fmt.Errorf("%w: introspected scopes differ from the request", ErrGCPScopeMismatch)
	}
	expires, err := strconv.ParseInt(reply.Exp, 10, 64)
	now := s.now()
	if err != nil || !time.Unix(expires, 0).After(now) || time.Unix(expires, 0).After(now.Add(scope.Lifetime+stsClockSkew)) {
		return fmt.Errorf("%w: introspected expiry exceeds the request", ErrGCPScopeMismatch)
	}
	return nil
}

// DefaultGCPTokenURL is the Google OAuth token endpoint a service account key
// signs in against.
const DefaultGCPTokenURL = "https://oauth2.googleapis.com/token" //nolint:gosec // G101 false positive: an endpoint URL, not a credential

// GCPSourceTokenFromKey returns a source-token getter that signs in as the
// service account in keyJSON (the downloaded key file) with the JWT-bearer
// grant. The identity it signs in as only needs the token-creator role on the
// account that is impersonated. The key's own token_uri is ignored so a
// stored key cannot redirect the sign-in; tokenURL replaces the default in
// tests.
func GCPSourceTokenFromKey(keyJSON []byte, tokenURL string, client *http.Client) func(namespace string) ([]byte, error) {
	if tokenURL == "" {
		tokenURL = DefaultGCPTokenURL
	}
	client = credentialHTTPClient(client)
	return func(string) ([]byte, error) {
		var key struct {
			Type        string `json:"type"`
			ClientEmail string `json:"client_email"`
			PrivateKey  string `json:"private_key"`
		}
		if err := json.Unmarshal(keyJSON, &key); err != nil || key.Type != "service_account" || key.ClientEmail == "" {
			return nil, errors.New("gcp_impersonation: the stored key is not a service account key file")
		}
		rsaKey, err := ParseGitHubAppPrivateKey([]byte(key.PrivateKey))
		if err != nil {
			return nil, errors.New("gcp_impersonation: the service account key has no usable RSA private key")
		}
		now := time.Now()
		claims, err := json.Marshal(map[string]any{
			"iss": key.ClientEmail, "scope": "https://www.googleapis.com/auth/cloud-platform",
			"aud": tokenURL, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
		if err != nil {
			return nil, err
		}
		input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			return nil, fmt.Errorf("gcp_impersonation: sign assertion: %w", err)
		}
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {input + "." + base64.RawURLEncoding.EncodeToString(sig)}}
		req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("gcp_impersonation: sign in: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if err != nil || resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("gcp_impersonation: sign in returned %d", resp.StatusCode)
		}
		var reply struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(body, &reply) != nil || reply.AccessToken == "" {
			return nil, errors.New("gcp_impersonation: sign in returned no access token")
		}
		return []byte(reply.AccessToken), nil
	}
}
