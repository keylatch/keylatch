// Package opconnect implements the Backend interface using the 1Password Connect REST API.
// Uses net/http directly — no SDK.
//
// Security invariants:
//   - Never log plaintext secret values; use HMAC of path for audit.
//   - runner.OK is checked before returning plaintext.
package opconnect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/runner"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// compile-time interface check.
var _ backend.Backend = (*OPConnectBackend)(nil)

// Options configures an OPConnectBackend.
type Options struct {
	ConnectURL string
	Token      string
	VaultID    string

	// HTTPClient allows injecting a custom HTTP client (used in tests).
	HTTPClient *http.Client
}

// opItem represents a 1Password item returned by the Connect API.
type opItem struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Category string    `json:"category"`
	Fields   []opField `json:"fields,omitempty"`
}

// opField represents a field within a 1Password item.
type opField struct {
	ID      string `json:"id,omitempty"`
	Label   string `json:"label,omitempty"`
	Purpose string `json:"purpose,omitempty"`
	Type    string `json:"type,omitempty"`
	Value   string `json:"value,omitempty"`
}

// OPConnectBackend implements backend.Backend using the 1Password Connect REST API.
type OPConnectBackend struct {
	opts       Options
	httpClient *http.Client
	host       string
}

// Open creates and configures an OPConnectBackend.
func Open(opts Options) (*OPConnectBackend, error) {
	if opts.ConnectURL == "" {
		return nil, fmt.Errorf("op-connect backend: connect_url is required")
	}
	if opts.Token == "" {
		return nil, fmt.Errorf("op-connect backend: token is required")
	}
	if opts.VaultID == "" {
		return nil, fmt.Errorf("op-connect backend: vault_id is required")
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	u, err := url.Parse(opts.ConnectURL)
	if err != nil {
		return nil, fmt.Errorf("op-connect backend: parse connect_url: %w", err)
	}

	return &OPConnectBackend{
		opts:       opts,
		httpClient: httpClient,
		host:       u.Host,
	}, nil
}

// Name implements backend.Backend.
func (b *OPConnectBackend) Name() string { return "op-connect" }

// Capabilities implements backend.Backend.
func (b *OPConnectBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapNetworkedFetch,
	}
}

// ID returns a stable unique identifier for this backend instance.
func (b *OPConnectBackend) ID() string {
	return fmt.Sprintf("op-connect:%s/%s", b.host, b.opts.VaultID)
}

// Get retrieves a secret value from 1Password Connect.
// It searches for an item by title matching path and returns the PASSWORD field.
func (b *OPConnectBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	items, err := b.listItems(ctx, path)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("op-connect Get %q: %w", path, err)
	}

	for _, item := range items {
		if item.Title == path {
			// Fetch full item to get fields.
			full, err := b.getItem(ctx, item.ID)
			if err != nil {
				return nil, backend.Meta{}, fmt.Errorf("op-connect Get %q: %w", path, err)
			}
			val := extractOPValue(full.Fields, path)
			if val == "" {
				return nil, backend.Meta{}, fmt.Errorf("%w: %s (no PASSWORD field)", backend.ErrNotFound, path)
			}
			m := backend.Meta{
				Path:     path,
				Backend:  "op-connect",
				Accessor: backend.ID(item.ID),
				Version:  1,
			}
			return []byte(val), m, nil
		}
	}

	return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
}

// Set creates a new LOGIN item in 1Password Connect.
func (b *OPConnectBackend) Set(ctx context.Context, path string, value []byte, _ backend.Meta) error {
	item := opItem{
		Title:    path,
		Category: "LOGIN",
		Fields: []opField{
			{
				Label:   path,
				Purpose: "PASSWORD",
				Type:    "CONCEALED",
				Value:   string(value),
			},
		},
	}
	body, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("op-connect Set %q: marshal: %w", path, err)
	}

	endpoint := fmt.Sprintf("%s/v1/vaults/%s/items", b.opts.ConnectURL, b.opts.VaultID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("op-connect Set %q: create request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+b.opts.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("op-connect Set %q: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("op-connect Set %q: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

// Delete removes a 1Password item by title.
func (b *OPConnectBackend) Delete(ctx context.Context, path string) error {
	items, err := b.listItems(ctx, path)
	if err != nil {
		return fmt.Errorf("op-connect Delete %q: list: %w", path, err)
	}

	for _, item := range items {
		if item.Title == path {
			endpoint := fmt.Sprintf("%s/v1/vaults/%s/items/%s",
				b.opts.ConnectURL, b.opts.VaultID, item.ID)
			req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
			if err != nil {
				return fmt.Errorf("op-connect Delete %q: create request: %w", path, err)
			}
			req.Header.Set("Authorization", "Bearer "+b.opts.Token)

			resp, err := b.httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("op-connect Delete %q: %w", path, err)
			}
			resp.Body.Close() //nolint:errcheck

			if resp.StatusCode == http.StatusNotFound {
				return fmt.Errorf("%w: %s", backend.ErrNotFound, path)
			}
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
				return fmt.Errorf("op-connect Delete %q: HTTP %d", path, resp.StatusCode)
			}
			return nil
		}
	}

	return fmt.Errorf("%w: %s", backend.ErrNotFound, path)
}

// List returns metadata-only entries (titles) from 1Password Connect.
func (b *OPConnectBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	items, err := b.listItems(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("op-connect List: %w", err)
	}

	var entries []backend.Entry
	for _, item := range items {
		if prefix != "" && (len(item.Title) < len(prefix) || item.Title[:len(prefix)] != prefix) {
			continue
		}
		entries = append(entries, backend.Entry{
			Meta: backend.Meta{
				Path:     item.Title,
				Backend:  "op-connect",
				Accessor: backend.ID(item.ID),
				Version:  1,
			},
			Exists: true,
		})
	}
	return entries, nil
}

// GetMeta is not supported by this backend.
func (b *OPConnectBackend) GetMeta(_ context.Context, _ string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported by this backend.
func (b *OPConnectBackend) SetMeta(_ context.Context, _ string, _ vmeta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta is not supported by this backend.
func (b *OPConnectBackend) ListMeta(_ context.Context, _ string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported by this backend.
func (b *OPConnectBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported by this backend.
func (b *OPConnectBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported by this backend.
func (b *OPConnectBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// Close is a no-op for the op-connect backend.
func (b *OPConnectBackend) Close() error { return nil }

// listItems fetches items from the Connect vault, optionally filtered by title.
func (b *OPConnectBackend) listItems(ctx context.Context, title string) ([]opItem, error) {
	endpoint := fmt.Sprintf("%s/v1/vaults/%s/items", b.opts.ConnectURL, b.opts.VaultID)
	if title != "" {
		endpoint += "?title=" + url.QueryEscape(title)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.opts.Token)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var items []opItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return items, nil
}

// getItem fetches a single item by ID.
func (b *OPConnectBackend) getItem(ctx context.Context, itemID string) (opItem, error) {
	endpoint := fmt.Sprintf("%s/v1/vaults/%s/items/%s",
		b.opts.ConnectURL, b.opts.VaultID, itemID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return opItem{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.opts.Token)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return opItem{}, fmt.Errorf("HTTP: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return opItem{}, fmt.Errorf("%w: item %s", backend.ErrNotFound, itemID)
	}
	if resp.StatusCode != http.StatusOK {
		return opItem{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return opItem{}, fmt.Errorf("read response: %w", err)
	}

	var item opItem
	if err := json.Unmarshal(raw, &item); err != nil {
		return opItem{}, fmt.Errorf("decode response: %w", err)
	}
	return item, nil
}

// extractOPValue returns the PASSWORD field value, or the field labelled with path,
// or the first field value.
func extractOPValue(fields []opField, path string) string {
	for _, f := range fields {
		if f.Purpose == "PASSWORD" {
			return f.Value
		}
	}
	for _, f := range fields {
		if f.Label == path {
			return f.Value
		}
	}
	if len(fields) > 0 {
		return fields[0].Value
	}
	return ""
}
