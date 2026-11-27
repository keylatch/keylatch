package azurekv

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractVaultName_Cases(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://myvault.vault.azure.net":  "myvault",
		"https://myvault.vault.azure.net/": "myvault",
		"://bad url":                       "://bad url",
		"https://single":                   "single",
	}
	for in, want := range cases {
		assert.Equal(t, want, extractVaultName(in), in)
	}
}

func TestExtractSecretNameFromID_Cases(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://v.vault.azure.net/secrets/name/ver": "name",
		"https://v.vault.azure.net/secrets/name":     "name",
		"https://v.vault.azure.net/keys/name/ver":    "https://v.vault.azure.net/keys/name/ver",
		"https://v.vault.azure.net/secrets":          "https://v.vault.azure.net/secrets",
		"%zz":                                        "%zz",
	}
	for in, want := range cases {
		assert.Equal(t, want, extractSecretNameFromID(in), in)
	}
}

func TestIsAzureNotFound_Classification(t *testing.T) {
	t.Parallel()
	assert.False(t, isAzureNotFound(nil))
	assert.True(t, isAzureNotFound(fmt.Errorf("wrapped: %w", &azcore.ResponseError{StatusCode: 404})))
	assert.False(t, isAzureNotFound(&azcore.ResponseError{StatusCode: 403}))
	assert.True(t, isAzureNotFound(errors.New("SecretNotFound: gone")))
	assert.True(t, isAzureNotFound(errors.New("status 404")))
	assert.False(t, isAzureNotFound(errors.New("connection refused")))
}

func TestOpen_InvalidTenantRejected(t *testing.T) {
	t.Parallel()
	_, err := Open(Options{
		VaultURL:     "https://v.vault.azure.net",
		TenantID:     "not a valid tenant!",
		ClientID:     "cid",
		ClientSecret: "cs",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create credential")
	assert.NotContains(t, err.Error(), ": cs")
}
