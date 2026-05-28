package azurekv_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/azurekv"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

func openMockAzureBackend(t *testing.T, secrets map[string]string) *azurekv.AzureKeyVaultBackend {
	t.Helper()
	mock := newMockAzureClient(secrets)
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)
	return b
}

func TestAzureName(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	assert.Equal(t, "azure-kv", b.Name())
}

func TestAzureID(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	assert.Contains(t, b.ID(), "azure-kv")
	assert.Contains(t, b.ID(), "myvault")
}

func TestAzureClose(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	assert.NoError(t, b.Close())
	assert.NoError(t, b.Close()) // idempotent
}

func TestAzureSet(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	err := b.Set(context.Background(), "new-key", []byte("new-value"), backend.Meta{})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "new-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("new-value"), val)
	assert.Equal(t, "azure-kv", meta.Backend)
}

func TestAzureSet_Update(t *testing.T) {
	b := openMockAzureBackend(t, map[string]string{"existing-key": "original"})
	err := b.Set(context.Background(), "existing-key", []byte("updated"), backend.Meta{})
	require.NoError(t, err)

	val, _, err := b.Get(context.Background(), "existing-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("updated"), val)
}

func TestAzureDelete_Success(t *testing.T) {
	b := openMockAzureBackend(t, map[string]string{"del-key": "del-val"})
	err := b.Delete(context.Background(), "del-key")
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "del-key")
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestAzureDelete_NotFound(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	err := b.Delete(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestAzureGet_NilValue(t *testing.T) {
	mock := &nilValueAzureClient{}
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "any-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

// nilValueAzureClient returns a successful response but with nil Value.
type nilValueAzureClient struct{}

func (m *nilValueAzureClient) GetSecret(_ context.Context, _ string, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return azsecrets.GetSecretResponse{
		Secret: azsecrets.Secret{Value: nil},
	}, nil
}
func (m *nilValueAzureClient) SetSecret(_ context.Context, name string, params azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	val := ""
	if params.Value != nil {
		val = *params.Value
	}
	return azsecrets.SetSecretResponse{Secret: azsecrets.Secret{Value: &val}}, nil
}
func (m *nilValueAzureClient) DeleteSecret(_ context.Context, _ string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	return azsecrets.DeleteSecretResponse{}, nil
}
func (m *nilValueAzureClient) NewListSecretPropertiesPager(_ *azsecrets.ListSecretPropertiesOptions) azurekv.AzurePager {
	return &emptyPager{}
}

type emptyPager struct{ done bool }

func (p *emptyPager) HasPage() bool { return false }
func (p *emptyPager) NextPage(_ context.Context) (azsecrets.ListSecretPropertiesResponse, error) {
	return azsecrets.ListSecretPropertiesResponse{}, fmt.Errorf("no more pages")
}

func TestAzureSet_Error(t *testing.T) {
	mock := &errAzureClient{}
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	err = b.Set(context.Background(), "key", []byte("val"), backend.Meta{})
	require.Error(t, err)
}

// errAzureClient always returns errors.
type errAzureClient struct{}

func (m *errAzureClient) GetSecret(_ context.Context, _ string, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 500, ErrorCode: "InternalServerError"}
}
func (m *errAzureClient) SetSecret(_ context.Context, _ string, _ azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	return azsecrets.SetSecretResponse{}, fmt.Errorf("set error")
}
func (m *errAzureClient) DeleteSecret(_ context.Context, _ string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	return azsecrets.DeleteSecretResponse{}, fmt.Errorf("delete error")
}
func (m *errAzureClient) NewListSecretPropertiesPager(_ *azsecrets.ListSecretPropertiesOptions) azurekv.AzurePager {
	return &errPager{}
}

type errPager struct{ called bool }

func (p *errPager) HasPage() bool {
	if !p.called {
		p.called = true
		return true
	}
	return false
}
func (p *errPager) NextPage(_ context.Context) (azsecrets.ListSecretPropertiesResponse, error) {
	return azsecrets.ListSecretPropertiesResponse{}, fmt.Errorf("list page error")
}

func TestAzureList_Error(t *testing.T) {
	mock := &errAzureClient{}
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	_, err = b.List(context.Background(), "")
	require.Error(t, err)
}

func TestAzureDelete_OtherError(t *testing.T) {
	mock := &errAzureClient{}
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	err = b.Delete(context.Background(), "key")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
}

func TestAzureGet_OtherError(t *testing.T) {
	mock := &errAzureClient{}
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "key")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
}

func TestAzureOpen_MissingVaultURL(t *testing.T) {
	_, err := azurekv.Open(azurekv.Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault_url")
}

func TestAzureGetMeta_NotSupported(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	_, err := b.GetMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAzureSetMeta_NotSupported(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	err := b.SetMeta(context.Background(), "any/path", vmeta.Meta{})
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAzureListMeta_NotSupported(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	_, err := b.ListMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAzureGetVersioned_NotSupported(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	_, err := b.GetVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAzureSetVersioned_NotSupported(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	err := b.SetVersioned(context.Background(), "any/path", 1, []byte("val"))
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAzureDeleteVersioned_NotSupported(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	err := b.DeleteVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestAzureList_WithPrefix(t *testing.T) {
	b := openMockAzureBackend(t, map[string]string{
		"myapp-key1": "v1",
		"myapp-key2": "v2",
		"other-key":  "v3",
	})
	entries, err := b.List(context.Background(), "myapp")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.True(t, e.Exists)
	}
}

func TestAzureCapabilities_HasCapList(t *testing.T) {
	b := openMockAzureBackend(t, nil)
	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapList {
			found = true
			break
		}
	}
	assert.True(t, found, "azure-kv must report CapList")
}

func TestAzureList_NilProperties(t *testing.T) {
	mock := &nilPropAzureClient{}
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	// Nil entries should be skipped.
	assert.Len(t, entries, 0)
}

// nilPropAzureClient returns a pager that yields nil properties.
type nilPropAzureClient struct{}

func (m *nilPropAzureClient) GetSecret(_ context.Context, _ string, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 404, ErrorCode: "SecretNotFound"}
}
func (m *nilPropAzureClient) SetSecret(_ context.Context, _ string, _ azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	return azsecrets.SetSecretResponse{}, nil
}
func (m *nilPropAzureClient) DeleteSecret(_ context.Context, _ string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	return azsecrets.DeleteSecretResponse{}, nil
}
func (m *nilPropAzureClient) NewListSecretPropertiesPager(_ *azsecrets.ListSecretPropertiesOptions) azurekv.AzurePager {
	return &nilPropPager{}
}

type nilPropPager struct{ done bool }

func (p *nilPropPager) HasPage() bool {
	if !p.done {
		p.done = true
		return true
	}
	return false
}
func (p *nilPropPager) NextPage(_ context.Context) (azsecrets.ListSecretPropertiesResponse, error) {
	// Return a page with a nil property.
	return azsecrets.ListSecretPropertiesResponse{
		SecretPropertiesListResult: azsecrets.SecretPropertiesListResult{
			Value: []*azsecrets.SecretProperties{nil},
		},
	}, nil
}
