// Package strategies implements ExchangeStrategy for each supported provider.
package strategies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// OAuthRefreshStrategy exchanges a refresh token for a short-lived access token
// using the OAuth 2.0 refresh_token grant.
type OAuthRefreshStrategy struct {
	// provider is the provider slug (e.g. "google").
	provider string
	// tokenEndpoint is the full URL of the token endpoint.
	tokenEndpoint string
	// clientID is the OAuth client ID.
	clientID string
	// clientSecret is the OAuth client secret.
	clientSecret string
	// getRefreshToken is called to retrieve the refresh token for a given actor/namespace.
	getRefreshToken func(actor, namespace string) ([]byte, error)
	// httpClient is the HTTP client used for token requests.
	httpClient *http.Client
	// scopes, when set, are requested with the refresh and checked against the
	// scope the provider reports for the access token.
	scopes []string
}

// ErrOAuthScopeMismatch is returned when the provider issued an access token
// whose scope is missing or wider than the one requested. No token is
// returned with it.
var ErrOAuthScopeMismatch = errors.New("oauth_refresh: issued token scope does not match the requested scope")

// OAuthOption configures an OAuthRefreshStrategy.
type OAuthOption func(*OAuthRefreshStrategy)

// WithScopes limits the access token to scopes. The provider's reply must
// report a scope within them or the exchange fails closed.
func WithScopes(scopes ...string) OAuthOption {
	return func(s *OAuthRefreshStrategy) { s.scopes = scopes }
}

// WithOAuthHTTPClient replaces the HTTP client.
func WithOAuthHTTPClient(c *http.Client) OAuthOption {
	return func(s *OAuthRefreshStrategy) { s.httpClient = credentialHTTPClient(c) }
}

// NewOAuthRefreshStrategy creates a strategy that POSTs to tokenEndpoint.
func NewOAuthRefreshStrategy(
	provider, tokenEndpoint, clientID, clientSecret string,
	getRefreshToken func(actor, namespace string) ([]byte, error),
	opts ...OAuthOption,
) *OAuthRefreshStrategy {
	s := &OAuthRefreshStrategy{
		provider:        provider,
		tokenEndpoint:   tokenEndpoint,
		clientID:        clientID,
		clientSecret:    clientSecret,
		getRefreshToken: getRefreshToken,
		httpClient:      credentialHTTPClient(nil),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Provider returns the provider slug.
func (s *OAuthRefreshStrategy) Provider() string { return s.provider }

// Exchange performs the token refresh.
// Returns ErrExpiredRefreshToken for invalid_grant / invalid_token responses.
// Returns an error if access_token is absent from the response.
// Token bytes are stored in ExchangeResult.tokenBytes (unexported).
func (s *OAuthRefreshStrategy) Exchange(ctx context.Context, actor, sessionID, namespace string) (broker.ExchangeResult, error) {
	tok, err := s.refresh(ctx, actor, namespace)
	if err != nil {
		return broker.ExchangeResult{}, err
	}
	defer tok.Zero()
	ttl := time.Until(tok.ExpiresAt)
	return broker.NewExchangeResult(s.provider, "", ttl, FreshExchangeType(), tok.AccessToken), nil
}

// OAuthToken is one access token obtained with a refresh token.
type OAuthToken struct {
	AccessToken []byte
	ExpiresAt   time.Time
	// Scopes are the scopes the provider reported; empty when none were
	// requested and the provider reported none.
	Scopes        []string
	lifetimeKnown bool
}

// Zero wipes the token.
func (t *OAuthToken) Zero() { clear(t.AccessToken) }

// MintScoped refreshes an access token for a run. Unlike Exchange it refuses a
// token that lives longer than maxLifetime (at most MaxTokenLifetime unless
// the caller opted in to longer), because the provider, not Keylatch, picks
// the lifetime and the token cannot be shortened or revoked here.
func (s *OAuthRefreshStrategy) MintScoped(ctx context.Context, actor, namespace string, maxLifetime time.Duration) (OAuthToken, error) {
	if maxLifetime <= 0 {
		maxLifetime = MaxTokenLifetime
	}
	tok, err := s.refresh(ctx, actor, namespace)
	if err != nil {
		return OAuthToken{}, err
	}
	if !tok.lifetimeKnown || len(s.scopes) == 0 || !subset(s.scopes, tok.Scopes) {
		tok.Zero()
		return OAuthToken{}, fmt.Errorf("%w: a scoped mint requires the requested scopes and an explicit expiry", ErrOAuthScopeMismatch)
	}
	if time.Until(tok.ExpiresAt) > maxLifetime+stsClockSkew {
		tok.Zero()
		return OAuthToken{}, fmt.Errorf("%w: token lives until %s, longer than the %s allowed", ErrOAuthScopeMismatch, tok.ExpiresAt.UTC().Format(time.RFC3339), maxLifetime)
	}
	return tok, nil
}

func (s *OAuthRefreshStrategy) refresh(ctx context.Context, actor, namespace string) (OAuthToken, error) {
	refreshToken, err := s.getRefreshToken(actor, namespace)
	if err != nil {
		return OAuthToken{}, fmt.Errorf("oauth_refresh: get refresh token: %w", err)
	}
	defer zeroBytes(refreshToken)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", string(refreshToken))
	form.Set("client_id", s.clientID)
	form.Set("client_secret", s.clientSecret)
	if len(s.scopes) > 0 {
		form.Set("scope", strings.Join(s.scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return OAuthToken{}, fmt.Errorf("oauth_refresh: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return OAuthToken{}, fmt.Errorf("oauth_refresh: http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return OAuthToken{}, fmt.Errorf("oauth_refresh: read response: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return OAuthToken{}, fmt.Errorf("oauth_refresh: parse response: %w", err)
	}

	// Check for expired/revoked refresh token.
	if errCode, _ := payload["error"].(string); errCode == "invalid_grant" || errCode == "invalid_token" {
		return OAuthToken{}, broker.ErrExpiredRefreshToken
	}

	if resp.StatusCode != http.StatusOK {
		return OAuthToken{}, fmt.Errorf("oauth_refresh: server returned %d", resp.StatusCode)
	}

	accessToken, _ := payload["access_token"].(string)
	if accessToken == "" {
		return OAuthToken{}, fmt.Errorf("oauth_refresh: missing access_token in response")
	}

	granted, _ := payload["scope"].(string)
	fields := strings.Fields(granted)
	if len(s.scopes) > 0 && (len(fields) == 0 || !subset(fields, s.scopes)) {
		return OAuthToken{}, fmt.Errorf("%w: requested %q, issued %q", ErrOAuthScopeMismatch, strings.Join(s.scopes, " "), granted)
	}

	ttl := time.Hour // default
	expiresIn, lifetimeKnown := payload["expires_in"].(float64)
	lifetimeKnown = lifetimeKnown && expiresIn >= 1 && expiresIn <= float64((1<<63-1)/int64(time.Second)) && expiresIn == float64(int64(expiresIn))
	if lifetimeKnown {
		ttl = time.Duration(expiresIn) * time.Second
	}
	return OAuthToken{AccessToken: []byte(accessToken), ExpiresAt: time.Now().Add(ttl), Scopes: fields, lifetimeKnown: lifetimeKnown}, nil
}

// FreshExchangeType returns the FreshExchange constant from the parent package.
// Defined here to avoid import cycles; callers use the value directly.
func FreshExchangeType() broker.ExchangeType {
	return broker.FreshExchange
}

// subset reports whether every element of got is in want.
func subset(got, want []string) bool {
	for _, g := range got {
		if !slices.Contains(want, g) {
			return false
		}
	}
	return true
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
