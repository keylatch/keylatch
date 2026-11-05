package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPProxyBindingOfATemplate(t *testing.T) {
	require.NoError(t, registry.InitFromConfig(context.Background(), func(string) string { return "" }))
	b, path, err := mcpProxyBinding(context.Background(), &fieldStore{}, "github-app", "team")
	require.NoError(t, err)
	assert.Contains(t, b.Hosts, "api.github.com")
	tmpl, err := registry.Get("github-app")
	require.NoError(t, err)
	assert.Equal(t, connections.SecretFieldPath("team", tmpl.Category, "github-app", "token"), path("token"))
}

func TestMCPProxyBindingOfAnUnknownConnection(t *testing.T) {
	_, _, err := mcpProxyBinding(context.Background(), &fieldStore{}, "no-such-connection", "default")
	require.ErrorIs(t, err, registry.ErrNoBinding)
}

// rotationStore keeps the values Set writes so a test can read them back.
type rotationStore struct {
	fieldStore
	written map[string][]byte
	meta    backend.Meta
	setErr  error
}

func (s *rotationStore) Get(ctx context.Context, p string) ([]byte, backend.Meta, error) {
	v, _, err := s.fieldStore.Get(ctx, p)
	return v, s.meta, err
}

func (s *rotationStore) Set(_ context.Context, p string, v []byte, m backend.Meta) error {
	if s.setErr != nil {
		return s.setErr
	}
	s.written = map[string][]byte{p: v}
	s.meta = m
	return nil
}

func TestMCPProxyOAuthFlags(t *testing.T) {
	path := func(field string) string { return "ns/" + field }
	for name, tc := range map[string]struct {
		flags oauthFlags
		want  string
	}{
		"oauth flags without a grant": {oauthFlags{clientID: "c"}, "need --oauth"},
		"unknown grant":               {oauthFlags{grant: "password", clientID: "c"}, "must be refresh_token or client_credentials"},
		"no client id":                {oauthFlags{grant: "refresh_token"}, "--oauth-client-id"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.flags.config(&fieldStore{}, path)
			require.ErrorContains(t, err, tc.want)
		})
	}

	none, err := oauthFlags{}.config(&fieldStore{}, path)
	require.NoError(t, err)
	assert.Nil(t, none)

	cfg, err := oauthFlags{grant: "client_credentials", clientID: "c", tokenURL: "https://a.example/token", scope: "s"}.config(&fieldStore{}, path)
	require.NoError(t, err)
	assert.Equal(t, "client_credentials", cfg.Grant)
	assert.Equal(t, "c", cfg.ClientID)
	assert.Equal(t, "https://a.example/token", cfg.TokenURL)
	assert.Equal(t, "s", cfg.Scope)
}

func TestMCPProxyStoresARotatedRefreshToken(t *testing.T) {
	store := &rotationStore{fieldStore: fieldStore{m: map[string][]byte{"ns/token": []byte("old")}}, meta: backend.Meta{Version: 3}}
	cfg, err := oauthFlags{grant: "refresh_token", clientID: "c"}.config(store, func(f string) string { return "ns/" + f })
	require.NoError(t, err)

	require.NoError(t, cfg.Rotate(context.Background(), "token", []byte("new")))
	assert.Equal(t, map[string][]byte{"ns/token": []byte("new")}, store.written)
	assert.Equal(t, 3, store.meta.Version, "the replacement keeps the stored metadata")

	missing := &rotationStore{}
	cfg, err = oauthFlags{grant: "refresh_token", clientID: "c"}.config(missing, func(f string) string { return "ns/" + f })
	require.NoError(t, err)
	require.ErrorIs(t, cfg.Rotate(context.Background(), "token", []byte("new")), backend.ErrNotFound)

	failing := &rotationStore{fieldStore: fieldStore{m: map[string][]byte{"ns/token": []byte("old")}}, setErr: errors.New("read-only")}
	cfg, err = oauthFlags{grant: "refresh_token", clientID: "c"}.config(failing, func(f string) string { return "ns/" + f })
	require.NoError(t, err)
	require.ErrorContains(t, cfg.Rotate(context.Background(), "token", []byte("new")), "read-only")
}

func TestMCPProxyCommandIsRegistered(t *testing.T) {
	cmd := newMCPCmd()
	proxy, _, err := cmd.Find([]string{"proxy"})
	require.NoError(t, err)
	assert.Equal(t, "proxy", proxy.Name())
	require.NotNil(t, proxy.Flags().Lookup("url"))
	for _, f := range []string{"oauth", "oauth-client-id", "oauth-token-url", "oauth-scope"} {
		require.NotNil(t, proxy.Flags().Lookup(f), f)
	}
	assert.Contains(t, proxy.Long, "no token", "the help says the client's configuration holds no token")
}
