// Package vault implements the Backend interface using HashiCorp Vault KV secrets.
//
// Security invariants:
//   - Never log plaintext secret values; use HMAC of path for audit.
//   - AppRole tokens are revoked on Close.
//   - runner.OK is checked before returning plaintext.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/runner"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// compile-time interface check.
var _ backend.Backend = (*VaultBackend)(nil)

// Options configures a VaultBackend.
type Options struct {
	Address   string
	Token     string
	RoleID    string
	SecretID  string
	Mount     string // default "secret"
	KVVersion int    // 1 or 2; default 2
	Namespace string // Vault Enterprise namespace; empty = omit

	// HTTPClient allows injecting a custom HTTP client (used in tests).
	HTTPClient *http.Client
}

// VaultBackend implements backend.Backend using HashiCorp Vault KV secrets.
type VaultBackend struct {
	opts         Options
	client       *vaultapi.Client
	appRoleToken bool // true when token was obtained via AppRole login
}

// Open creates and configures a VaultBackend, performing AppRole login if credentials are set.
func Open(opts Options) (*VaultBackend, error) {
	if opts.Mount == "" {
		opts.Mount = "secret"
	}
	if opts.KVVersion == 0 {
		opts.KVVersion = 2
	}
	if opts.Address == "" {
		opts.Address = "http://127.0.0.1:8200"
	}

	cfg := vaultapi.DefaultConfig()
	cfg.Address = opts.Address
	if opts.HTTPClient != nil {
		cfg.HttpClient = opts.HTTPClient
	}

	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault backend: create client: %w", err)
	}

	if opts.Namespace != "" {
		client.SetNamespace(opts.Namespace)
	}

	b := &VaultBackend{opts: opts, client: client}

	// AppRole auth: if both RoleID and SecretID are set, login now.
	if opts.RoleID != "" && opts.SecretID != "" {
		token, err := b.appRoleLogin(context.Background())
		if err != nil {
			return nil, fmt.Errorf("vault backend: AppRole login: %w", err)
		}
		client.SetToken(token)
		b.appRoleToken = true
	} else if opts.Token != "" {
		client.SetToken(opts.Token)
	}

	return b, nil
}

// appRoleLogin exchanges RoleID+SecretID for a Vault token.
func (b *VaultBackend) appRoleLogin(ctx context.Context) (string, error) {
	payload := map[string]string{
		"role_id":   b.opts.RoleID,
		"secret_id": b.opts.SecretID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.opts.Address+"/v1/auth/approle/login",
		strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if b.opts.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.opts.Namespace)
	}

	httpClient := b.client.CloneConfig().HttpClient
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("AppRole login request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("AppRole login: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("AppRole login: read response: %w", err)
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("AppRole login: decode response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("AppRole login: no client_token in response")
	}
	return result.Auth.ClientToken, nil
}

// Name implements backend.Backend.
func (b *VaultBackend) Name() string { return "vault" }

// Capabilities implements backend.Backend.
func (b *VaultBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapNetworkedFetch,
	}
}

// ID returns a stable unique identifier for this backend instance.
func (b *VaultBackend) ID() string {
	if b.opts.Namespace != "" {
		return fmt.Sprintf("vault:%s/%s", b.opts.Address, b.opts.Namespace)
	}
	return fmt.Sprintf("vault:%s", b.opts.Address)
}

// secretPath returns the Vault KV path for the given key.
// KV v2: <mount>/data/<path>; KV v1: <mount>/<path>.
func (b *VaultBackend) secretPath(path string) string {
	if b.opts.KVVersion == 2 {
		return fmt.Sprintf("%s/data/%s", b.opts.Mount, path)
	}
	return fmt.Sprintf("%s/%s", b.opts.Mount, path)
}

// Get retrieves a secret from Vault. Plaintext is only returned when runner.OK.
func (b *VaultBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	if b.opts.KVVersion == 1 {
		return b.getV1(ctx, path)
	}

	// KV v2 path.
	secret, err := b.client.KVv2(b.opts.Mount).Get(ctx, path)
	if err != nil {
		if isVaultNotFound(err) {
			return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		}
		return nil, backend.Meta{}, fmt.Errorf("vault Get %q: %w", b.secretPath(path), err)
	}

	if secret == nil || secret.Data == nil {
		return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
	}

	// Extract "value" field, or first string field.
	val, err := extractValue(secret.Data)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("vault Get %q: %w", path, err)
	}

	m := backend.Meta{
		Path:    path,
		Backend: "vault",
		Version: 1,
	}
	return val, m, nil
}

// getV1 fetches a secret from a KV v1 mount.
func (b *VaultBackend) getV1(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	kvPath := fmt.Sprintf("%s/%s", b.opts.Mount, path)
	logical := b.client.Logical()
	secret, err := logical.ReadWithContext(ctx, kvPath)
	if err != nil {
		if isVaultNotFound(err) {
			return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		}
		return nil, backend.Meta{}, fmt.Errorf("vault Get v1 %q: %w", kvPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
	}

	val, err := extractValue(secret.Data)
	if err != nil {
		return nil, backend.Meta{}, fmt.Errorf("vault Get v1 %q: %w", path, err)
	}
	m := backend.Meta{Path: path, Backend: "vault", Version: 1}
	return val, m, nil
}

// Set writes a secret to Vault.
func (b *VaultBackend) Set(ctx context.Context, path string, value []byte, _ backend.Meta) error {
	data := map[string]interface{}{"value": string(value)}
	if b.opts.KVVersion == 2 {
		_, err := b.client.KVv2(b.opts.Mount).Put(ctx, path, data)
		if err != nil {
			return fmt.Errorf("vault Set %q: %w", path, err)
		}
		return nil
	}
	kvPath := fmt.Sprintf("%s/%s", b.opts.Mount, path)
	_, err := b.client.Logical().WriteWithContext(ctx, kvPath, data)
	if err != nil {
		return fmt.Errorf("vault Set v1 %q: %w", path, err)
	}
	return nil
}

// Delete removes a secret from Vault.
func (b *VaultBackend) Delete(ctx context.Context, path string) error {
	if b.opts.KVVersion == 2 {
		if err := b.client.KVv2(b.opts.Mount).Delete(ctx, path); err != nil {
			if isVaultNotFound(err) {
				return fmt.Errorf("%w: %s", backend.ErrNotFound, path)
			}
			return fmt.Errorf("vault Delete %q: %w", path, err)
		}
		return nil
	}
	kvPath := fmt.Sprintf("%s/%s", b.opts.Mount, path)
	_, err := b.client.Logical().DeleteWithContext(ctx, kvPath)
	if err != nil {
		if isVaultNotFound(err) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		}
		return fmt.Errorf("vault Delete v1 %q: %w", path, err)
	}
	return nil
}

// List returns metadata-only entries under the given prefix.
func (b *VaultBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	listPath := b.opts.Mount
	if b.opts.KVVersion == 2 {
		listPath = fmt.Sprintf("%s/metadata", b.opts.Mount)
	}
	if prefix != "" {
		listPath = fmt.Sprintf("%s/%s", listPath, prefix)
	}

	secret, err := b.client.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		if isVaultNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("vault List %q: %w", prefix, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}

	var entries []backend.Entry
	for _, k := range keys {
		ks, ok := k.(string)
		if !ok {
			continue
		}
		p := ks
		if prefix != "" {
			p = prefix + "/" + ks
		}
		entries = append(entries, backend.Entry{
			Meta:   backend.Meta{Path: p, Backend: "vault"},
			Exists: true,
		})
	}
	return entries, nil
}

// GetMeta is not supported by this backend.
func (b *VaultBackend) GetMeta(_ context.Context, _ string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported by this backend.
func (b *VaultBackend) SetMeta(_ context.Context, _ string, _ vmeta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta is not supported by this backend.
func (b *VaultBackend) ListMeta(_ context.Context, _ string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported by this backend.
func (b *VaultBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported by this backend.
func (b *VaultBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported by this backend.
func (b *VaultBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// Close revokes the AppRole token if one was obtained via AppRole login.
func (b *VaultBackend) Close() error {
	if !b.appRoleToken || b.client.Token() == "" {
		return nil
	}
	// Best-effort token revocation — ignore errors.
	_ = b.client.Auth().Token().RevokeSelfWithContext(context.Background(), b.client.Token())
	return nil
}

// extractValue returns the "value" field from Vault secret data, or the first
// string field if "value" is absent.
func extractValue(data map[string]interface{}) ([]byte, error) {
	if v, ok := data["value"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("value field is not a string")
		}
		return []byte(s), nil
	}
	for _, v := range data {
		if s, ok := v.(string); ok {
			return []byte(s), nil
		}
	}
	return nil, fmt.Errorf("no string value found in secret data")
}

// isVaultNotFound returns true when a Vault API error indicates the secret does not exist.
func isVaultNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "404") ||
		strings.Contains(msg, "secret not found") ||
		strings.Contains(msg, "no secret") ||
		strings.Contains(msg, "nil response")
}
