// Package infisical implements the Backend interface using the Infisical API v3.
// Uses net/http directly — no SDK.
//
// Security invariants:
//   - Never log plaintext secret values; use HMAC of path for audit.
//   - Access token is cached and refreshed on 401.
//   - runner.OK is checked before returning plaintext.
package infisical

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/runner"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// compile-time interface check.
var _ backend.Backend = (*InfisicalBackend)(nil)

const defaultBaseURL = "https://app.infisical.com"

// Options configures an InfisicalBackend.
type Options struct {
	BaseURL      string // default "https://app.infisical.com"
	ClientID     string
	ClientSecret string
	WorkspaceID  string
	Environment  string
	SecretPath   string // default "/"

	// HTTPClient allows injecting a custom HTTP client (used in tests).
	HTTPClient *http.Client
}

// InfisicalBackend implements backend.Backend using the Infisical API v3.
type InfisicalBackend struct {
	opts       Options
	httpClient *http.Client
	host       string

	mu          sync.Mutex
	accessToken string
}

// Open creates and configures an InfisicalBackend.
func Open(opts Options) (*InfisicalBackend, error) {
	if opts.BaseURL == "" {
		opts.BaseURL = defaultBaseURL
	}
	if opts.SecretPath == "" {
		opts.SecretPath = "/"
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("infisical backend: parse base_url: %w", err)
	}

	return &InfisicalBackend{
		opts:       opts,
		httpClient: httpClient,
		host:       u.Host,
	}, nil
}

// Name implements backend.Backend.
func (b *InfisicalBackend) Name() string { return "infisical" }

// Capabilities implements backend.Backend.
func (b *InfisicalBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapNetworkedFetch,
	}
}

// ID returns a stable unique identifier for this backend instance.
func (b *InfisicalBackend) ID() string {
	return fmt.Sprintf("infisical:%s/%s", b.host, b.opts.WorkspaceID)
}

// login performs Universal Auth and caches the access token.
func (b *InfisicalBackend) login(ctx context.Context) error {
	payload := map[string]string{
		"clientId":     b.opts.ClientID,
		"clientSecret": b.opts.ClientSecret,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("infisical login: marshal: %w", err)
	}

	endpoint := b.opts.BaseURL + "/api/v1/auth/universal-auth/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("infisical login: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("infisical login: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("infisical login: HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("infisical login: read response: %w", err)
	}

	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("infisical login: decode response: %w", err)
	}
	if result.AccessToken == "" {
		return fmt.Errorf("infisical login: no access token in response")
	}

	b.mu.Lock()
	b.accessToken = result.AccessToken
	b.mu.Unlock()
	return nil
}

// token returns the cached access token, logging in if needed.
func (b *InfisicalBackend) token(ctx context.Context) (string, error) {
	b.mu.Lock()
	tok := b.accessToken
	b.mu.Unlock()
	if tok != "" {
		return tok, nil
	}
	if err := b.login(ctx); err != nil {
		return "", err
	}
	b.mu.Lock()
	tok = b.accessToken
	b.mu.Unlock()
	return tok, nil
}

// doRequest performs an authenticated HTTP request, refreshing the token on 401.
func (b *InfisicalBackend) doRequest(ctx context.Context, method, endpoint string, body []byte) (*http.Response, error) {
	tok, err := b.token(ctx)
	if err != nil {
		return nil, err
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Refresh token and retry on 401.
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close() //nolint:errcheck
		b.mu.Lock()
		b.accessToken = ""
		b.mu.Unlock()
		if err := b.login(ctx); err != nil {
			return nil, fmt.Errorf("token refresh: %w", err)
		}
		tok, _ = b.token(ctx)

		var reqBody2 io.Reader
		if body != nil {
			reqBody2 = bytes.NewReader(body)
		}
		req2, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody2)
		if err != nil {
			return nil, fmt.Errorf("create retry request: %w", err)
		}
		req2.Header.Set("Authorization", "Bearer "+tok)
		if body != nil {
			req2.Header.Set("Content-Type", "application/json")
		}
		return b.httpClient.Do(req2)
	}

	return resp, nil
}

// Get retrieves a secret from Infisical.
// GET /api/v3/secrets/raw/<name>?workspaceId=<w>&environment=<e>&secretPath=<p>
func (b *InfisicalBackend) Get(ctx context.Context, name string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	endpoint := fmt.Sprintf("%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=%s",
		b.opts.BaseURL,
		url.PathEscape(name),
		url.QueryEscape(b.opts.WorkspaceID),
		url.QueryEscape(b.opts.Environment),
		url.QueryEscape(b.opts.SecretPath),
	)

	resp, err := b.doRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("infisical Get %q: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, backend.Meta{}, fmt.Errorf("infisical Get %q: HTTP %d", name, resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("infisical Get %q: read response: %w", name, err)
	}

	var result struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, backend.Meta{}, fmt.Errorf("infisical Get %q: decode response: %w", name, err)
	}

	m := backend.Meta{
		Path:    name,
		Backend: "infisical",
		Version: 1,
	}
	return []byte(result.Secret.SecretValue), m, nil
}

// Set creates or updates a secret in Infisical.
// POST /api/v3/secrets/raw/<name>
func (b *InfisicalBackend) Set(ctx context.Context, name string, value []byte, _ backend.Meta) error {
	payload := map[string]string{
		"workspaceId": b.opts.WorkspaceID,
		"environment": b.opts.Environment,
		"secretPath":  b.opts.SecretPath,
		"secretValue": string(value),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("infisical Set %q: marshal: %w", name, err)
	}

	endpoint := fmt.Sprintf("%s/api/v3/secrets/raw/%s",
		b.opts.BaseURL, url.PathEscape(name))

	resp, err := b.doRequest(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return fmt.Errorf("infisical Set %q: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("infisical Set %q: HTTP %d", name, resp.StatusCode)
	}
	return nil
}

// Delete removes a secret from Infisical.
// DELETE /api/v3/secrets/raw/<name>
func (b *InfisicalBackend) Delete(ctx context.Context, name string) error {
	payload := map[string]string{
		"workspaceId": b.opts.WorkspaceID,
		"environment": b.opts.Environment,
		"secretPath":  b.opts.SecretPath,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("infisical Delete %q: marshal: %w", name, err)
	}

	endpoint := fmt.Sprintf("%s/api/v3/secrets/raw/%s",
		b.opts.BaseURL, url.PathEscape(name))

	resp, err := b.doRequest(ctx, http.MethodDelete, endpoint, body)
	if err != nil {
		return fmt.Errorf("infisical Delete %q: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", backend.ErrNotFound, name)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("infisical Delete %q: HTTP %d", name, resp.StatusCode)
	}
	return nil
}

// List returns secret names from Infisical.
// GET /api/v3/secrets/raw?workspaceId=<w>&environment=<e>&secretPath=<p>
func (b *InfisicalBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	endpoint := fmt.Sprintf("%s/api/v3/secrets/raw?workspaceId=%s&environment=%s&secretPath=%s",
		b.opts.BaseURL,
		url.QueryEscape(b.opts.WorkspaceID),
		url.QueryEscape(b.opts.Environment),
		url.QueryEscape(b.opts.SecretPath),
	)

	resp, err := b.doRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("infisical List: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("infisical List: HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("infisical List: read response: %w", err)
	}

	var result struct {
		Secrets []struct {
			SecretKey string `json:"secretKey"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("infisical List: decode response: %w", err)
	}

	var entries []backend.Entry
	for _, s := range result.Secrets {
		if prefix != "" && !strings.HasPrefix(s.SecretKey, prefix) {
			continue
		}
		entries = append(entries, backend.Entry{
			Meta: backend.Meta{
				Path:    s.SecretKey,
				Backend: "infisical",
				Version: 1,
			},
			Exists: true,
		})
	}
	return entries, nil
}

// GetMeta is not supported by this backend.
func (b *InfisicalBackend) GetMeta(_ context.Context, _ string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported by this backend.
func (b *InfisicalBackend) SetMeta(_ context.Context, _ string, _ vmeta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta is not supported by this backend.
func (b *InfisicalBackend) ListMeta(_ context.Context, _ string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported by this backend.
func (b *InfisicalBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported by this backend.
func (b *InfisicalBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported by this backend.
func (b *InfisicalBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// Close is a no-op for the infisical backend.
func (b *InfisicalBackend) Close() error { return nil }
