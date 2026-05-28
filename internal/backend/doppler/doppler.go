// Package doppler implements the Backend interface using the Doppler REST API v3.
// Uses net/http directly — no SDK.
//
// Security invariants:
//   - Never log plaintext secret values; use HMAC of path for audit.
//   - runner.OK is checked before returning plaintext.
package doppler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/runner"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// compile-time interface check.
var _ backend.Backend = (*DopplerBackend)(nil)

const defaultBaseURL = "https://api.doppler.com"

// Options configures a DopplerBackend.
type Options struct {
	Token   string
	Project string
	Config  string
	BaseURL string // default "https://api.doppler.com"

	// HTTPClient allows injecting a custom HTTP client (used in tests).
	HTTPClient *http.Client
}

// DopplerBackend implements backend.Backend using the Doppler REST API v3.
type DopplerBackend struct {
	opts       Options
	httpClient *http.Client
}

// Open creates and configures a DopplerBackend.
func Open(opts Options) (*DopplerBackend, error) {
	if opts.Token == "" {
		return nil, fmt.Errorf("doppler backend: token is required")
	}
	if opts.Project == "" {
		return nil, fmt.Errorf("doppler backend: project is required")
	}
	if opts.Config == "" {
		return nil, fmt.Errorf("doppler backend: config is required")
	}
	if opts.BaseURL == "" {
		opts.BaseURL = defaultBaseURL
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &DopplerBackend{opts: opts, httpClient: httpClient}, nil
}

// Name implements backend.Backend.
func (b *DopplerBackend) Name() string { return "doppler" }

// Capabilities implements backend.Backend.
func (b *DopplerBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapNetworkedFetch,
	}
}

// ID returns a stable unique identifier for this backend instance.
func (b *DopplerBackend) ID() string {
	return fmt.Sprintf("doppler:%s/%s", b.opts.Project, b.opts.Config)
}

// Get retrieves a secret value from Doppler.
// GET /v3/configs/config/secret?project=<p>&config=<c>&name=<n>
func (b *DopplerBackend) Get(ctx context.Context, name string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	endpoint := fmt.Sprintf("%s/v3/configs/config/secret?project=%s&config=%s&name=%s",
		b.opts.BaseURL,
		url.QueryEscape(b.opts.Project),
		url.QueryEscape(b.opts.Config),
		url.QueryEscape(name),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("doppler Get %q: create request: %w", name, err)
	}
	req.Header.Set("Authorization", "Bearer "+b.opts.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("doppler Get %q: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, backend.Meta{}, fmt.Errorf("doppler Get %q: HTTP %d", name, resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("doppler Get %q: read response: %w", name, err)
	}

	var result struct {
		Value struct {
			Raw string `json:"raw"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, backend.Meta{}, fmt.Errorf("doppler Get %q: decode response: %w", name, err)
	}

	m := backend.Meta{
		Path:    name,
		Backend: "doppler",
		Version: 1,
	}
	return []byte(result.Value.Raw), m, nil
}

// Set creates or updates a secret in Doppler.
// POST /v3/configs/config/secrets with {"secrets": {"<name>": "<val>"}}
func (b *DopplerBackend) Set(ctx context.Context, name string, value []byte, _ backend.Meta) error {
	payload := map[string]interface{}{
		"project": b.opts.Project,
		"config":  b.opts.Config,
		"secrets": map[string]string{name: string(value)},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("doppler Set %q: marshal: %w", name, err)
	}

	endpoint := fmt.Sprintf("%s/v3/configs/config/secrets", b.opts.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("doppler Set %q: create request: %w", name, err)
	}
	req.Header.Set("Authorization", "Bearer "+b.opts.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("doppler Set %q: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("doppler Set %q: HTTP %d", name, resp.StatusCode)
	}
	return nil
}

// Delete removes a secret from Doppler.
// DELETE /v3/configs/config/secrets with {"secrets": ["<name>"]}
func (b *DopplerBackend) Delete(ctx context.Context, name string) error {
	payload := map[string]interface{}{
		"project": b.opts.Project,
		"config":  b.opts.Config,
		"secrets": []string{name},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("doppler Delete %q: marshal: %w", name, err)
	}

	endpoint := fmt.Sprintf("%s/v3/configs/config/secrets", b.opts.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("doppler Delete %q: create request: %w", name, err)
	}
	req.Header.Set("Authorization", "Bearer "+b.opts.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("doppler Delete %q: %w", name, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", backend.ErrNotFound, name)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("doppler Delete %q: HTTP %d", name, resp.StatusCode)
	}
	return nil
}

// List returns secret names (no values) from Doppler.
// GET /v3/configs/config/secrets?project=<p>&config=<c>
func (b *DopplerBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	endpoint := fmt.Sprintf("%s/v3/configs/config/secrets?project=%s&config=%s",
		b.opts.BaseURL,
		url.QueryEscape(b.opts.Project),
		url.QueryEscape(b.opts.Config),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("doppler List: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.opts.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doppler List: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doppler List: HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doppler List: read response: %w", err)
	}

	var result struct {
		Secrets map[string]struct {
			Raw string `json:"raw"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("doppler List: decode response: %w", err)
	}

	var entries []backend.Entry
	for name := range result.Secrets {
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		entries = append(entries, backend.Entry{
			Meta: backend.Meta{
				Path:    name,
				Backend: "doppler",
				Version: 1,
			},
			Exists: true,
		})
	}
	return entries, nil
}

// GetMeta is not supported by this backend.
func (b *DopplerBackend) GetMeta(_ context.Context, _ string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported by this backend.
func (b *DopplerBackend) SetMeta(_ context.Context, _ string, _ vmeta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta is not supported by this backend.
func (b *DopplerBackend) ListMeta(_ context.Context, _ string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported by this backend.
func (b *DopplerBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported by this backend.
func (b *DopplerBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported by this backend.
func (b *DopplerBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// Close is a no-op for the doppler backend.
func (b *DopplerBackend) Close() error { return nil }
