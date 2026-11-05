package connections

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxFailingSetStore fails Set for paths matching the predicate.
type mxFailingSetStore struct {
	*mockStore
	fail func(path string) bool
}

func (s *mxFailingSetStore) Set(ctx context.Context, path string, v []byte, m backend.Meta) error {
	if s.fail(path) {
		return errors.New("disk full")
	}
	return s.mockStore.Set(ctx, path, v, m)
}

func mxTemplateWithConfigField(t *testing.T) registry.ConnectionTemplate {
	t.Helper()
	for _, tmpl := range registry.List() {
		if len(tmpl.ConfigFields) > 0 && !tmpl.MultiAccount {
			return tmpl
		}
	}
	t.Skip("no registry template with config fields")
	return registry.ConnectionTemplate{}
}

func mxAllSecretFields(tmpl registry.ConnectionTemplate) map[string][]byte {
	fields := map[string][]byte{}
	for _, sf := range tmpl.SecretFields {
		fields[sf.Name] = []byte("v-" + sf.Name)
	}
	return fields
}

func TestConnect_WritesConfigFieldsUnderConfigPath(t *testing.T) {
	tmpl := mxTemplateWithConfigField(t)
	cf := tmpl.ConfigFields[0]
	fields := mxAllSecretFields(tmpl)
	fields[cf.Name] = []byte("explicit-config")

	store := newMockStore()
	conn, err := Connect(context.Background(), tmpl.Provider, ConnectOptions{NonInteractive: true, Fields: fields, Mode: "not-a-mode"}, store)
	require.NoError(t, err)
	assert.Equal(t, tmpl.RuntimeSupport.Preferred, conn.Runtime, "invalid modes fall back to the template preference")

	got, ok := store.storedValue(configFieldPath("default", tmpl.Category, tmpl.Provider, cf.Name))
	require.True(t, ok)
	assert.Equal(t, "explicit-config", string(got))

	// Delete removes config fields too.
	require.NoError(t, Delete(context.Background(), tmpl.Provider, "", "", store))
	_, ok = store.storedValue(configFieldPath("default", tmpl.Category, tmpl.Provider, cf.Name))
	assert.False(t, ok)
}

func TestConnect_StoreWriteFailures(t *testing.T) {
	tmpl := mxTemplateWithConfigField(t)
	cases := map[string]struct {
		fail    func(string) bool
		wantMsg string
	}{
		"secret field": {func(p string) bool { return !strings.Contains(p, "/config/") && !strings.HasSuffix(p, "/meta") }, "write field"},
		"config field": {func(p string) bool { return strings.Contains(p, "/config/") }, "write config field"},
		"metadata":     {func(p string) bool { return strings.HasSuffix(p, "/meta") }, "write connection metadata"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fields := mxAllSecretFields(tmpl)
			fields[tmpl.ConfigFields[0].Name] = []byte("cfg")
			store := &mxFailingSetStore{mockStore: newMockStore(), fail: tc.fail}
			_, err := Connect(context.Background(), tmpl.Provider, ConnectOptions{NonInteractive: true, Fields: fields}, store)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

func TestConnect_InteractiveMissingRequiredField(t *testing.T) {
	_, err := Connect(context.Background(), "openrouter", ConnectOptions{}, newMockStore())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--non-interactive")
}

func TestStatus_IncludesCustomConnections(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	require.NoError(t, store.Set(ctx, "default/custom/inhouse/meta", []byte(`{"provider":"inhouse","account":"default","namespace":"default","status":"untested"}`), backend.Meta{}))
	require.NoError(t, store.Set(ctx, "default/custom/broken/meta", []byte(`{not json`), backend.Meta{}))
	require.NoError(t, store.Set(ctx, "default/custom/not-meta-entry", []byte(`x`), backend.Meta{}))
	mxConnect(t, store, "openrouter")

	statuses, err := Status(ctx, StatusOptions{}, store)
	require.NoError(t, err)
	byProvider := map[string]ConnectionStatus{}
	for _, s := range statuses {
		byProvider[s.Connection.Provider] = s
	}
	require.Contains(t, byProvider, "inhouse")
	require.Contains(t, byProvider, "openrouter")
	assert.NotContains(t, byProvider, "broken", "unparseable metadata is skipped")
	assert.Empty(t, byProvider["inhouse"].Capabilities)
	assert.NotEmpty(t, byProvider["openrouter"].Capabilities)
}

func TestStatus_WithTestOfflineProbe(t *testing.T) {
	store := newMockStore()
	mxConnect(t, store, "auth0")
	statuses, err := Status(context.Background(), StatusOptions{Namespace: "default", Test: true}, store)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, TestStatusNetworkError, statuses[0].Connection.Status)
}

func TestStatus_CorruptRegistryMetaSkipped(t *testing.T) {
	store := newMockStore()
	require.NoError(t, store.Set(context.Background(), "default/ai/openrouter/meta", []byte("{"), backend.Meta{}))
	statuses, err := Status(context.Background(), StatusOptions{}, store)
	require.NoError(t, err)
	assert.Empty(t, statuses)
}

func TestDescribe_ConnectionPathAndUnknown(t *testing.T) {
	tmpl, masked, err := Describe(context.Background(), "default/openrouter/default", newMockStore())
	require.NoError(t, err)
	assert.Equal(t, "openrouter", tmpl.Provider)
	for _, v := range masked {
		assert.Equal(t, "****", v)
	}

	_, _, err = Describe(context.Background(), "nope-provider", newMockStore())
	assert.ErrorIs(t, err, ErrProviderNotFound)
}

func TestPathHelpers_DefaultCategory(t *testing.T) {
	assert.Equal(t, "ns/ai/p/meta", connectionMetaPath("ns", "", "p"))
	assert.Equal(t, "ns/ai/p/f", secretFieldPath("ns", "", "p", "f"))
	assert.Equal(t, "ns/ai/p/config/f", configFieldPath("ns", "", "p", "f"))
}
