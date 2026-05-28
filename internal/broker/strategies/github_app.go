package strategies

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// GitHubAppInstallationStrategy exchanges a GitHub App private key for an
// installation access token via POST /app/installations/{id}/access_tokens.
type GitHubAppInstallationStrategy struct {
	provider       string
	appID          string
	installationID string
	privateKey     *rsa.PrivateKey
	httpClient     *http.Client
	// endpointFmt is a fmt.Sprintf pattern for the access_tokens URL.
	// Default: "https://api.github.com/app/installations/%s/access_tokens"
	endpointFmt string
}

// NewGitHubAppInstallationStrategy creates the strategy.
// privateKey must be a valid RSA private key loaded from a PEM file.
func NewGitHubAppInstallationStrategy(appID, installationID string, privateKey *rsa.PrivateKey) *GitHubAppInstallationStrategy {
	return &GitHubAppInstallationStrategy{
		provider:       "github",
		appID:          appID,
		installationID: installationID,
		privateKey:     privateKey,
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		endpointFmt:    "https://api.github.com/app/installations/%s/access_tokens",
	}
}

// Provider returns the provider slug.
func (s *GitHubAppInstallationStrategy) Provider() string { return s.provider }

// Exchange signs a JWT and exchanges it for an installation access token.
// Returns ErrRevokedSession when the installation access is denied.
func (s *GitHubAppInstallationStrategy) Exchange(ctx context.Context, _, _, _ string) (broker.ExchangeResult, error) {
	jwt, err := s.signJWT()
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("github_app: sign JWT: %w", err)
	}
	jwtBytes := []byte(jwt)
	defer zeroBytes(jwtBytes)

	endpoint := fmt.Sprintf(s.endpointFmt, s.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("{}"))
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("github_app: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("github_app: http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("github_app: read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return broker.ExchangeResult{}, broker.ErrRevokedSession
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return broker.ExchangeResult{}, fmt.Errorf("github_app: server returned %d", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("github_app: parse response: %w", err)
	}

	token, _ := payload["token"].(string)
	if token == "" {
		return broker.ExchangeResult{}, fmt.Errorf("github_app: missing token in response")
	}

	ttl := time.Hour
	if expiresAt, ok := payload["expires_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			if d := time.Until(t); d > 0 {
				ttl = d
			}
		}
	}

	tokenBytes := []byte(token)
	result := broker.NewExchangeResult(s.provider, "", ttl, broker.FreshExchange, tokenBytes)
	zeroBytes(tokenBytes)
	return result, nil
}

// signJWT creates a RS256-signed JWT for GitHub App authentication.
// The JWT has a 10-minute expiry per GitHub requirements.
func (s *GitHubAppInstallationStrategy) signJWT() (string, error) {
	now := time.Now()
	headerJSON := `{"alg":"RS256","typ":"JWT"}`
	claimsJSON := fmt.Sprintf(`{"iat":%d,"exp":%d,"iss":"%s"}`,
		now.Add(-60*time.Second).Unix(),
		now.Add(9*time.Minute).Unix(),
		s.appID,
	)

	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payload := base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	sigInput := header + "." + payload

	digest := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("rsa sign: %w", err)
	}
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
