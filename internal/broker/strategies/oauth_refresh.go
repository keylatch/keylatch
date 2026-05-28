// Package strategies implements ExchangeStrategy for each supported provider.
package strategies

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
}

// NewOAuthRefreshStrategy creates a strategy that POSTs to tokenEndpoint.
func NewOAuthRefreshStrategy(
	provider, tokenEndpoint, clientID, clientSecret string,
	getRefreshToken func(actor, namespace string) ([]byte, error),
) *OAuthRefreshStrategy {
	return &OAuthRefreshStrategy{
		provider:        provider,
		tokenEndpoint:   tokenEndpoint,
		clientID:        clientID,
		clientSecret:    clientSecret,
		getRefreshToken: getRefreshToken,
		httpClient:      &http.Client{Timeout: 15 * time.Second},
	}
}

// Provider returns the provider slug.
func (s *OAuthRefreshStrategy) Provider() string { return s.provider }

// Exchange performs the token refresh.
// Returns ErrExpiredRefreshToken for invalid_grant / invalid_token responses.
// Returns an error if access_token is absent from the response.
// Token bytes are stored in ExchangeResult.tokenBytes (unexported).
func (s *OAuthRefreshStrategy) Exchange(ctx context.Context, actor, sessionID, namespace string) (broker.ExchangeResult, error) {
	refreshToken, err := s.getRefreshToken(actor, namespace)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("oauth_refresh: get refresh token: %w", err)
	}
	defer zeroBytes(refreshToken)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", string(refreshToken))
	form.Set("client_id", s.clientID)
	form.Set("client_secret", s.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("oauth_refresh: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("oauth_refresh: http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("oauth_refresh: read response: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("oauth_refresh: parse response: %w", err)
	}

	// Check for expired/revoked refresh token.
	if errCode, _ := payload["error"].(string); errCode == "invalid_grant" || errCode == "invalid_token" {
		return broker.ExchangeResult{}, broker.ErrExpiredRefreshToken
	}

	if resp.StatusCode != http.StatusOK {
		return broker.ExchangeResult{}, fmt.Errorf("oauth_refresh: server returned %d", resp.StatusCode)
	}

	accessToken, _ := payload["access_token"].(string)
	if accessToken == "" {
		return broker.ExchangeResult{}, fmt.Errorf("oauth_refresh: missing access_token in response")
	}

	// Parse TTL.
	ttl := time.Hour // default
	if expiresIn, ok := payload["expires_in"].(float64); ok && expiresIn > 0 {
		ttl = time.Duration(expiresIn) * time.Second
	}

	tokenBytes := []byte(accessToken)
	// Zero the string contents via the byte slice; we clear the string reference below.
	result := broker.NewExchangeResult(s.provider, "", ttl, FreshExchangeType(), tokenBytes)

	// Zero local copy.
	zeroBytes(tokenBytes)

	return result, nil
}

// FreshExchangeType returns the FreshExchange constant from the parent package.
// Defined here to avoid import cycles; callers use the value directly.
func FreshExchangeType() broker.ExchangeType {
	return broker.FreshExchange
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
