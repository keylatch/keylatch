package cli

import (
	"context"
	"testing"

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

func TestMCPProxyCommandIsRegistered(t *testing.T) {
	cmd := newMCPCmd()
	proxy, _, err := cmd.Find([]string{"proxy"})
	require.NoError(t, err)
	assert.Equal(t, "proxy", proxy.Name())
	require.NotNil(t, proxy.Flags().Lookup("url"))
	assert.Contains(t, proxy.Long, "no token", "the help says the client's configuration holds no token")
}
