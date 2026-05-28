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

const (
	dropboxTokenEndpoint = "https://api.dropboxapi.com/oauth2/token" //nolint:gosec // G101 false positive: this is an OAuth endpoint URL, not a credential
	dropboxDefaultTTL    = 4 * time.Hour
)

// DropboxOAuthStrategy extends OAuth refresh for Dropbox.
// When expires_in is absent from the response, a default TTL of 4h is used.
type DropboxOAuthStrategy struct {
	provider        string
	clientID        string
	clientSecret    string
	getRefreshToken func(actor, namespace string) ([]byte, error)
	httpClient      *http.Client
}

// NewDropboxOAuthStrategy creates a DropboxOAuthStrategy.
func NewDropboxOAuthStrategy(
	clientID, clientSecret string,
	getRefreshToken func(actor, namespace string) ([]byte, error),
) *DropboxOAuthStrategy {
	return &DropboxOAuthStrategy{
		provider:        "dropbox",
		clientID:        clientID,
		clientSecret:    clientSecret,
		getRefreshToken: getRefreshToken,
		httpClient:      &http.Client{Timeout: 15 * time.Second},
	}
}

// Provider returns "dropbox".
func (s *DropboxOAuthStrategy) Provider() string { return s.provider }

// Exchange performs the Dropbox OAuth refresh.
// Uses dropboxDefaultTTL when expires_in is absent.
func (s *DropboxOAuthStrategy) Exchange(ctx context.Context, actor, _, namespace string) (broker.ExchangeResult, error) {
	refreshToken, err := s.getRefreshToken(actor, namespace)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("dropbox: get refresh token: %w", err)
	}
	defer zeroBytes(refreshToken)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", string(refreshToken))
	form.Set("client_id", s.clientID)
	form.Set("client_secret", s.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dropboxTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("dropbox: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("dropbox: http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("dropbox: read response: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("dropbox: parse response: %w", err)
	}

	if errCode, _ := payload["error"].(string); errCode == "invalid_grant" || errCode == "invalid_token" {
		return broker.ExchangeResult{}, broker.ErrExpiredRefreshToken
	}
	if resp.StatusCode != http.StatusOK {
		return broker.ExchangeResult{}, fmt.Errorf("dropbox: server returned %d", resp.StatusCode)
	}

	accessToken, _ := payload["access_token"].(string)
	if accessToken == "" {
		return broker.ExchangeResult{}, fmt.Errorf("dropbox: missing access_token in response")
	}

	ttl := dropboxDefaultTTL
	if expiresIn, ok := payload["expires_in"].(float64); ok && expiresIn > 0 {
		ttl = time.Duration(expiresIn) * time.Second
	}

	tokenBytes := []byte(accessToken)
	result := broker.NewExchangeResult(s.provider, "", ttl, broker.FreshExchange, tokenBytes)
	zeroBytes(tokenBytes)
	return result, nil
}
