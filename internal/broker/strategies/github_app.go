package strategies

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// DefaultGitHubAPIBase is the GitHub REST API root.
const DefaultGitHubAPIBase = "https://api.github.com"

// MaxGitHubAppTokenLifetime is the longest lifetime GitHub gives an
// installation token; a reply promising more is not from GitHub's contract.
const MaxGitHubAppTokenLifetime = time.Hour

// expirySkew absorbs clock drift between this host and GitHub when the
// reply's expires_at is compared against the allowed lifetime.
const expirySkew = 2 * time.Minute

// ErrScopeMismatch is returned when GitHub issued a token whose repository,
// permissions or lifetime differ from the request. The token has already
// been revoked (or revocation was attempted) when this error is returned.
var ErrScopeMismatch = errors.New("github_app: issued token does not match the requested scope")

// GitHubAppInstallationStrategy exchanges a GitHub App private key for an
// installation access token via POST /app/installations/{id}/access_tokens.
// The JWT is signed in-process; the private key is never sent anywhere.
type GitHubAppInstallationStrategy struct {
	provider       string
	appID          string
	installationID string
	privateKey     *rsa.PrivateKey
	httpClient     *http.Client
	apiBase        string
	now            func() time.Time
}

// GitHubAppOption configures a GitHubAppInstallationStrategy.
type GitHubAppOption func(*GitHubAppInstallationStrategy)

// WithGitHubAPIBase points the strategy at another API root, such as a
// GitHub Enterprise Server API URL.
func WithGitHubAPIBase(base string) GitHubAppOption {
	return func(s *GitHubAppInstallationStrategy) { s.apiBase = strings.TrimRight(base, "/") }
}

// WithGitHubHTTPClient replaces the HTTP client.
func WithGitHubHTTPClient(c *http.Client) GitHubAppOption {
	return func(s *GitHubAppInstallationStrategy) { s.httpClient = c }
}

// NewGitHubAppInstallationStrategy creates the strategy.
// privateKey must be a valid RSA private key loaded from a PEM file.
func NewGitHubAppInstallationStrategy(appID, installationID string, privateKey *rsa.PrivateKey, opts ...GitHubAppOption) *GitHubAppInstallationStrategy {
	s := &GitHubAppInstallationStrategy{
		provider:       "github",
		appID:          appID,
		installationID: installationID,
		privateKey:     privateKey,
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		apiBase:        DefaultGitHubAPIBase,
		now:            time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ParseGitHubAppPrivateKey parses a PEM-encoded PKCS#1 or PKCS#8 RSA key.
func ParseGitHubAppPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("github_app: private key is not PEM-encoded")
	}
	defer clear(block.Bytes)
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("github_app: private key is neither PKCS#1 nor PKCS#8")
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github_app: private key is not an RSA key")
	}
	return k, nil
}

// Provider returns the provider slug.
func (s *GitHubAppInstallationStrategy) Provider() string { return s.provider }

// Exchange signs a JWT and exchanges it for an installation access token.
// Returns ErrRevokedSession when the installation access is denied.
func (s *GitHubAppInstallationStrategy) Exchange(ctx context.Context, _, _, _ string) (broker.ExchangeResult, error) {
	status, body, err := s.postAccessToken(ctx, []byte("{}"))
	if err != nil {
		return broker.ExchangeResult{}, err
	}
	defer clear(body)

	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return broker.ExchangeResult{}, broker.ErrRevokedSession
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return broker.ExchangeResult{}, fmt.Errorf("github_app: server returned %d", status)
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

// GitHubAppScope is the scope of one installation token: exactly one
// repository ("owner/name") and the permissions to grant on it.
type GitHubAppScope struct {
	Repository  string
	Permissions map[string]string
}

// GitHubAppToken is a scoped installation token whose scope was verified
// against the request.
type GitHubAppToken struct {
	Token       []byte
	ExpiresAt   time.Time
	Repository  string
	Permissions map[string]string
}

// Zero overwrites the token bytes.
func (t *GitHubAppToken) Zero() { clear(t.Token) }

type accessTokenReply struct {
	Token        string            `json:"token"`
	ExpiresAt    string            `json:"expires_at"`
	Permissions  map[string]string `json:"permissions"`
	Repositories []struct {
		FullName string `json:"full_name"`
	} `json:"repositories"`
}

// MintScoped requests an installation token limited to scope. The reply
// must name exactly the requested repository and permissions and expire
// within maxLifetime (capped at one hour); otherwise the token is revoked
// with DELETE /installation/token and ErrScopeMismatch is returned. Nothing
// is cached: every call mints a fresh token.
func (s *GitHubAppInstallationStrategy) MintScoped(ctx context.Context, scope GitHubAppScope, maxLifetime time.Duration) (GitHubAppToken, error) {
	owner, name, ok := strings.Cut(scope.Repository, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return GitHubAppToken{}, fmt.Errorf("github_app: repository %q is not owner/name", scope.Repository)
	}
	if len(scope.Permissions) == 0 {
		return GitHubAppToken{}, errors.New("github_app: at least one permission is required")
	}
	if maxLifetime <= 0 || maxLifetime > MaxGitHubAppTokenLifetime {
		maxLifetime = MaxGitHubAppTokenLifetime
	}

	reqBody, err := json.Marshal(struct {
		Repositories []string          `json:"repositories"`
		Permissions  map[string]string `json:"permissions"`
	}{[]string{name}, scope.Permissions})
	if err != nil {
		return GitHubAppToken{}, fmt.Errorf("github_app: encode request: %w", err)
	}

	status, body, err := s.postAccessToken(ctx, reqBody)
	if err != nil {
		return GitHubAppToken{}, err
	}
	defer clear(body)
	if status != http.StatusCreated && status != http.StatusOK {
		return GitHubAppToken{}, fmt.Errorf("github_app: GitHub refused the token request (HTTP %d)", status)
	}

	var reply accessTokenReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return GitHubAppToken{}, errors.New("github_app: GitHub reply is not valid JSON")
	}
	if reply.Token == "" {
		return GitHubAppToken{}, errors.New("github_app: GitHub reply has no token")
	}
	token := []byte(reply.Token)
	reply.Token = ""

	expiresAt, verr := s.verifyReply(scope, reply, maxLifetime)
	if verr != nil {
		rerr := s.revoke(ctx, token)
		clear(token)
		if rerr != nil {
			return GitHubAppToken{}, fmt.Errorf("%w: %v; revoking it failed: %v", ErrScopeMismatch, verr, rerr)
		}
		return GitHubAppToken{}, fmt.Errorf("%w: %v; the token was revoked", ErrScopeMismatch, verr)
	}

	return GitHubAppToken{
		Token:       token,
		ExpiresAt:   expiresAt,
		Repository:  reply.Repositories[0].FullName,
		Permissions: maps.Clone(reply.Permissions),
	}, nil
}

func (s *GitHubAppInstallationStrategy) verifyReply(scope GitHubAppScope, reply accessTokenReply, maxLifetime time.Duration) (time.Time, error) {
	if len(reply.Repositories) != 1 {
		return time.Time{}, fmt.Errorf("reply covers %d repositories, want 1", len(reply.Repositories))
	}
	if !strings.EqualFold(reply.Repositories[0].FullName, scope.Repository) {
		return time.Time{}, fmt.Errorf("reply repository %q differs from %q", reply.Repositories[0].FullName, scope.Repository)
	}
	if !maps.Equal(reply.Permissions, scope.Permissions) {
		return time.Time{}, errors.New("reply permissions differ from the requested permissions")
	}
	expiresAt, err := time.Parse(time.RFC3339, reply.ExpiresAt)
	if err != nil {
		return time.Time{}, errors.New("reply has no valid expires_at")
	}
	now := s.now()
	if !expiresAt.After(now) {
		return time.Time{}, errors.New("reply token is already expired")
	}
	if expiresAt.Sub(now) > maxLifetime+expirySkew {
		return time.Time{}, fmt.Errorf("reply token lives %s, longer than the allowed %s", expiresAt.Sub(now).Round(time.Second), maxLifetime)
	}
	return expiresAt, nil
}

// Revoke invalidates an installation token with DELETE /installation/token.
func (s *GitHubAppInstallationStrategy) Revoke(ctx context.Context, token []byte) error {
	return s.revoke(ctx, token)
}

func (s *GitHubAppInstallationStrategy) revoke(ctx context.Context, token []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.apiBase+"/installation/token", nil)
	if err != nil {
		return fmt.Errorf("build revoke request: %w", err)
	}
	setGitHubHeaders(req)
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return errors.New("revoke request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *GitHubAppInstallationStrategy) postAccessToken(ctx context.Context, body []byte) (int, []byte, error) {
	jwt, err := s.signJWT()
	if err != nil {
		return 0, nil, fmt.Errorf("github_app: sign JWT: %w", err)
	}
	endpoint := s.apiBase + "/app/installations/" + s.installationID + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("github_app: build request: %w", err)
	}
	setGitHubHeaders(req)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("github_app: http request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return 0, nil, fmt.Errorf("github_app: read response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

// SignedAppJWT returns a short-lived RS256 JWT that authenticates as the App
// itself, for calls such as GET /app.
func (s *GitHubAppInstallationStrategy) SignedAppJWT() (string, error) { return s.signJWT() }

// signJWT creates a RS256-signed JWT for GitHub App authentication.
// iat is backdated a minute for clock drift; GitHub caps exp at 10 minutes.
func (s *GitHubAppInstallationStrategy) signJWT() (string, error) {
	now := s.now()
	claims, err := json.Marshal(struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}{now.Add(-60 * time.Second).Unix(), now.Add(9 * time.Minute).Unix(), s.appID})
	if err != nil {
		return "", fmt.Errorf("encode claims: %w", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(claims)
	sigInput := header + "." + payload

	digest := sha256.Sum256([]byte(sigInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("rsa sign: %w", err)
	}
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func setGitHubHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}
