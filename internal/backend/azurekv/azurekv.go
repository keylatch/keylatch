// Package azurekv implements the Backend interface using Azure Key Vault.
//
// Security invariants:
//   - Never log plaintext secret values; use HMAC of path for audit.
//   - runner.OK is checked before returning plaintext.
package azurekv

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/runner"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// compile-time interface check.
var _ backend.Backend = (*AzureKeyVaultBackend)(nil)

// AzureSecretsClient is the interface satisfied by the Azure SDK client and by test mocks.
type AzureSecretsClient interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
	DeleteSecret(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error)
	NewListSecretPropertiesPager(options *azsecrets.ListSecretPropertiesOptions) AzurePager
}

// AzurePager abstracts the Azure SDK pager.
type AzurePager interface {
	HasPage() bool
	NextPage(ctx context.Context) (azsecrets.ListSecretPropertiesResponse, error)
}

// Options configures an AzureKeyVaultBackend.
type Options struct {
	VaultURL     string
	TenantID     string
	ClientID     string
	ClientSecret string

	// Client allows injecting a mock client for tests.
	Client AzureSecretsClient
}

// AzureKeyVaultBackend implements backend.Backend using Azure Key Vault.
type AzureKeyVaultBackend struct {
	vaultName string
	client    AzureSecretsClient
}

// sdkClientWrapper wraps the Azure SDK client to satisfy AzureSecretsClient.
type sdkClientWrapper struct {
	inner *azsecrets.Client
}

func (w *sdkClientWrapper) GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return w.inner.GetSecret(ctx, name, version, options)
}

func (w *sdkClientWrapper) SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	return w.inner.SetSecret(ctx, name, parameters, options)
}

func (w *sdkClientWrapper) DeleteSecret(ctx context.Context, name string, options *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	return w.inner.DeleteSecret(ctx, name, options)
}

func (w *sdkClientWrapper) NewListSecretPropertiesPager(options *azsecrets.ListSecretPropertiesOptions) AzurePager {
	return &sdkPagerWrapper{inner: w.inner.NewListSecretPropertiesPager(options)}
}

// sdkPagerWrapper wraps the Azure SDK concrete pager type.
type sdkPagerWrapper struct {
	inner *azruntime.Pager[azsecrets.ListSecretPropertiesResponse]
}

func (p *sdkPagerWrapper) HasPage() bool {
	return p.inner.More()
}

func (p *sdkPagerWrapper) NextPage(ctx context.Context) (azsecrets.ListSecretPropertiesResponse, error) {
	return p.inner.NextPage(ctx)
}

// Open creates and configures an AzureKeyVaultBackend.
func Open(opts Options) (*AzureKeyVaultBackend, error) {
	if opts.VaultURL == "" {
		return nil, fmt.Errorf("azure-kv backend: vault_url is required")
	}

	vaultName := extractVaultName(opts.VaultURL)

	if opts.Client != nil {
		return &AzureKeyVaultBackend{
			vaultName: vaultName,
			client:    opts.Client,
		}, nil
	}

	var cred azcore.TokenCredential
	var err error

	if opts.TenantID != "" && opts.ClientID != "" && opts.ClientSecret != "" {
		cred, err = azidentity.NewClientSecretCredential(opts.TenantID, opts.ClientID, opts.ClientSecret, nil)
	} else {
		cred, err = azidentity.NewDefaultAzureCredential(nil)
	}
	if err != nil {
		return nil, fmt.Errorf("azure-kv backend: create credential: %w", err)
	}

	inner, err := azsecrets.NewClient(opts.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kv backend: create client: %w", err)
	}

	return &AzureKeyVaultBackend{
		vaultName: vaultName,
		client:    &sdkClientWrapper{inner: inner},
	}, nil
}

// Name implements backend.Backend.
func (b *AzureKeyVaultBackend) Name() string { return "azure-kv" }

// Capabilities implements backend.Backend.
func (b *AzureKeyVaultBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapNetworkedFetch,
	}
}

// ID returns a stable unique identifier for this backend instance.
func (b *AzureKeyVaultBackend) ID() string {
	return fmt.Sprintf("azure-kv:%s", b.vaultName)
}

// Get retrieves the latest version of a secret from Azure Key Vault.
func (b *AzureKeyVaultBackend) Get(ctx context.Context, name string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	resp, err := b.client.GetSecret(ctx, name, "", nil)
	if err != nil {
		if isAzureNotFound(err) {
			return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, name)
		}
		return nil, backend.Meta{}, fmt.Errorf("azure-kv Get %q: %w", name, err)
	}

	if resp.Value == nil {
		return nil, backend.Meta{}, fmt.Errorf("%w: %s (nil value)", backend.ErrNotFound, name)
	}

	m := backend.Meta{
		Path:    name,
		Backend: "azure-kv",
		Version: 1,
	}
	return []byte(*resp.Value), m, nil
}

// Set creates or updates a secret in Azure Key Vault.
func (b *AzureKeyVaultBackend) Set(ctx context.Context, name string, value []byte, _ backend.Meta) error {
	strVal := string(value)
	_, err := b.client.SetSecret(ctx, name, azsecrets.SetSecretParameters{
		Value: &strVal,
	}, nil)
	if err != nil {
		return fmt.Errorf("azure-kv Set %q: %w", name, err)
	}
	return nil
}

// Delete removes a secret from Azure Key Vault.
func (b *AzureKeyVaultBackend) Delete(ctx context.Context, name string) error {
	_, err := b.client.DeleteSecret(ctx, name, nil)
	if err != nil {
		if isAzureNotFound(err) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, name)
		}
		return fmt.Errorf("azure-kv Delete %q: %w", name, err)
	}
	return nil
}

// List returns metadata-only entries (names) from Azure Key Vault.
func (b *AzureKeyVaultBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	pager := b.client.NewListSecretPropertiesPager(nil)
	var entries []backend.Entry

	for pager.HasPage() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure-kv List: %w", err)
		}
		for _, props := range page.Value {
			if props == nil || props.ID == nil {
				continue
			}
			name := extractSecretNameFromID(string(*props.ID))
			if prefix != "" && !strings.HasPrefix(name, prefix) {
				continue
			}
			entries = append(entries, backend.Entry{
				Meta: backend.Meta{
					Path:    name,
					Backend: "azure-kv",
					Version: 1,
				},
				Exists: true,
			})
		}
	}
	return entries, nil
}

// GetMeta is not supported by this backend.
func (b *AzureKeyVaultBackend) GetMeta(_ context.Context, _ string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported by this backend.
func (b *AzureKeyVaultBackend) SetMeta(_ context.Context, _ string, _ vmeta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta is not supported by this backend.
func (b *AzureKeyVaultBackend) ListMeta(_ context.Context, _ string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported by this backend.
func (b *AzureKeyVaultBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported by this backend.
func (b *AzureKeyVaultBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported by this backend.
func (b *AzureKeyVaultBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// Close is a no-op for the azure-kv backend.
func (b *AzureKeyVaultBackend) Close() error { return nil }

// extractVaultName extracts the vault name from a vault URL like
// "https://myvault.vault.azure.net".
func extractVaultName(vaultURL string) string {
	u, err := url.Parse(vaultURL)
	if err != nil {
		return vaultURL
	}
	host := u.Hostname()
	parts := strings.SplitN(host, ".", 2)
	return parts[0]
}

// extractSecretNameFromID extracts the secret name from a full secret ID URL like
// "https://myvault.vault.azure.net/secrets/myname/version".
func extractSecretNameFromID(id string) string {
	// Parse as URL and extract the second path segment ("/secrets/<name>/...").
	u, err := url.Parse(id)
	if err != nil {
		return id
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "secrets" {
		return parts[1]
	}
	return id
}

// isAzureNotFound returns true when an Azure error indicates the resource does not exist.
func isAzureNotFound(err error) bool {
	if err == nil {
		return false
	}
	var respErr *azcore.ResponseError
	if ok := isResponseError(err, &respErr); ok {
		return respErr.StatusCode == 404
	}
	msg := err.Error()
	return strings.Contains(msg, "404") || strings.Contains(msg, "SecretNotFound")
}

// isResponseError checks if err wraps an *azcore.ResponseError.
func isResponseError(err error, target **azcore.ResponseError) bool {
	return errors.As(err, target)
}
