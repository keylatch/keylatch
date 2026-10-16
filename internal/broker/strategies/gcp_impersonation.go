package strategies

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultGCPIAMCredentialsEndpoint is the IAM Service Account Credentials API root.
const DefaultGCPIAMCredentialsEndpoint = "https://iamcredentials.googleapis.com"

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

// NewGCPImpersonationStrategy creates the strategy for one service account
// (its email address).
func NewGCPImpersonationStrategy(serviceAccount string, getSourceToken func(namespace string) ([]byte, error), opts ...GCPOption) *GCPImpersonationStrategy {
	s := &GCPImpersonationStrategy{
		serviceAccount: serviceAccount,
		endpoint:       DefaultGCPIAMCredentialsEndpoint,
		getSourceToken: getSourceToken,
		httpClient:     &http.Client{Timeout: 15 * time.Second},
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
	if scope.Lifetime == 0 {
		scope.Lifetime = MaxGCPTokenLifetime
	}
	if scope.Lifetime < 0 || scope.Lifetime > MaxGCPTokenLifetime {
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
	return GCPToken{AccessToken: []byte(reply.AccessToken), ExpiresAt: exp}, nil
}
