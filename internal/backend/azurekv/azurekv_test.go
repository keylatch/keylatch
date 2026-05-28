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
)

// mockAzureClient is a test double for AzureSecretsClient.
type mockAzureClient struct {
	secrets map[string]string
}

func newMockAzureClient(secrets map[string]string) *mockAzureClient {
	if secrets == nil {
		secrets = make(map[string]string)
	}
	return &mockAzureClient{secrets: secrets}
}

func (m *mockAzureClient) GetSecret(_ context.Context, name string, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	val, ok := m.secrets[name]
	if !ok {
		return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 404, ErrorCode: "SecretNotFound"}
	}
	return azsecrets.GetSecretResponse{
		Secret: azsecrets.Secret{
			Value: &val,
		},
	}, nil
}

func (m *mockAzureClient) SetSecret(_ context.Context, name string, parameters azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	if parameters.Value != nil {
		m.secrets[name] = *parameters.Value
	}
	val := m.secrets[name]
	return azsecrets.SetSecretResponse{
		Secret: azsecrets.Secret{Value: &val},
	}, nil
}

func (m *mockAzureClient) DeleteSecret(_ context.Context, name string, _ *azsecrets.DeleteSecretOptions) (azsecrets.DeleteSecretResponse, error) {
	if _, ok := m.secrets[name]; !ok {
		return azsecrets.DeleteSecretResponse{}, &azcore.ResponseError{StatusCode: 404, ErrorCode: "SecretNotFound"}
	}
	delete(m.secrets, name)
	return azsecrets.DeleteSecretResponse{}, nil
}

func (m *mockAzureClient) NewListSecretPropertiesPager(_ *azsecrets.ListSecretPropertiesOptions) azurekv.AzurePager {
	return &mockPager{secrets: m.secrets, idx: 0}
}

// mockPager is a test double for AzurePager.
type mockPager struct {
	secrets map[string]string
	idx     int
	keys    []string
	built   bool
}

func (p *mockPager) HasPage() bool {
	if !p.built {
		for k := range p.secrets {
			p.keys = append(p.keys, k)
		}
		p.built = true
	}
	return p.idx < len(p.keys)
}

func (p *mockPager) NextPage(_ context.Context) (azsecrets.ListSecretPropertiesResponse, error) {
	if !p.HasPage() {
		return azsecrets.ListSecretPropertiesResponse{}, fmt.Errorf("no more pages")
	}
	name := p.keys[p.idx]
	p.idx++
	idStr := azsecrets.ID("https://myvault.vault.azure.net/secrets/" + name)
	return azsecrets.ListSecretPropertiesResponse{
		SecretPropertiesListResult: azsecrets.SecretPropertiesListResult{
			Value: []*azsecrets.SecretProperties{
				{ID: &idStr},
			},
		},
	}, nil
}

func TestAzureGet(t *testing.T) {
	mock := newMockAzureClient(map[string]string{"myapp-key": "azure-secret"})
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "myapp-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("azure-secret"), val)
	assert.Equal(t, "azure-kv", meta.Backend)
}

func TestAzureGet_NotFound(t *testing.T) {
	mock := newMockAzureClient(nil)
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "missing-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestAzureList(t *testing.T) {
	mock := newMockAzureClient(map[string]string{
		"myapp-key1": "val1",
		"myapp-key2": "val2",
	})
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestAzureCapabilities(t *testing.T) {
	mock := newMockAzureClient(nil)
	b, err := azurekv.Open(azurekv.Options{
		VaultURL: "https://myvault.vault.azure.net",
		Client:   mock,
	})
	require.NoError(t, err)

	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapNetworkedFetch {
			found = true
			break
		}
	}
	assert.True(t, found, "azure-kv must report CapNetworkedFetch")
}
