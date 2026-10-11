package validate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxFlakyStore fails Get for non-meta paths and/or List for chosen prefixes.
type mxFlakyStore struct {
	*mockStore
	getErr     error
	listFailOn func(prefix string) bool
}

func (s *mxFlakyStore) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if s.getErr != nil {
		return nil, backend.Meta{}, s.getErr
	}
	return s.mockStore.Get(ctx, path)
}

func (s *mxFlakyStore) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	if s.listFailOn != nil && s.listFailOn(prefix) {
		return nil, errors.New("list failed")
	}
	return s.mockStore.List(ctx, prefix)
}

func TestValidateConnection_UnknownProvider(t *testing.T) {
	_, err := ValidateConnection(context.Background(), "", "no-such-provider-mx", "", newMockStore())
	assert.ErrorIs(t, err, connections.ErrProviderNotFound)
}

func TestValidateConnection_VaultReadErrorIsReported(t *testing.T) {
	store := &mxFlakyStore{mockStore: newMockStore(), getErr: errors.New("keychain locked")}
	issues, err := ValidateConnection(context.Background(), "", "openrouter", "", store)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "vault read error", issues[0].Message)
	assert.True(t, issues[0].IsError)
	assert.NotContains(t, issues[0].Message, "keychain locked", "backend error text is not surfaced")
}

func TestValidateConnection_OverbroadScopesWarn(t *testing.T) {
	require.NoError(t, registry.Register(registry.ConnectionTemplate{
		Provider:        "mx-validate-broad",
		DisplayName:     "Broad",
		SecretFields:    []registry.SecretField{{Name: "token", Required: true}, {Name: "optional"}},
		OverbroadScopes: []string{"admin:org", "repo"},
	}))
	store := newMockStore()
	require.NoError(t, store.Set(context.Background(), "ns/ai/mx-validate-broad/token", []byte("v"), backend.Meta{}))

	issues, err := ValidateConnection(context.Background(), "ns", "mx-validate-broad", "", store)
	require.NoError(t, err)
	require.Len(t, issues, 2, "present required field and optional field produce no errors")
	for _, is := range issues {
		assert.Equal(t, "warning", is.Severity)
		assert.False(t, is.IsError)
		assert.Contains(t, is.Message, "overbroad scope")
	}
}

func TestValidateStore_ListFailuresAreTolerated(t *testing.T) {
	ctx := context.Background()
	base := newMockStore()
	require.NoError(t, base.Set(ctx, "default/ai/openrouter/meta", []byte(`{}`), backend.Meta{}))

	allFail := &mxFlakyStore{mockStore: base, listFailOn: func(string) bool { return true }}
	issues, err := ValidateStore(ctx, ValidateOptions{}, allFail)
	require.NoError(t, err)
	assert.Empty(t, issues, "an unlistable store yields no connections to validate")

	configFail := &mxFlakyStore{mockStore: base, listFailOn: func(p string) bool { return strings.Contains(p, "/config/") }}
	issues, err = ValidateStore(ctx, ValidateOptions{Strict: true}, configFail)
	require.NoError(t, err)
	var fields []string
	for _, is := range issues {
		fields = append(fields, is.Field)
	}
	assert.Contains(t, fields, "api_key", "missing secret is still reported when the config scan fails")
}

func TestSecretFieldPath_DefaultCategory(t *testing.T) {
	assert.Equal(t, "ns/ai/p/f", secretFieldPath("ns", "", "p", "f"))
}
