package installer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/harness/merge"
)

func TestProxyInstallRoundTrip(t *testing.T) {
	for _, id := range []string{"claude-code", "cursor", "gemini-cli", "codex", "opencode", "copilot-cli", "antigravity", "windsurf"} {
		t.Run(id, func(t *testing.T) {
			d, ok := harness.Lookup(id)
			require.True(t, ok)
			o := Options{Env: testEnv(t.TempDir()), Server: Server{Command: testBinary}, Parts: Parts{MCP: true},
				Proxies: []Proxy{{Connection: "docs.remote", URL: "https://mcp.example.test/api"}}}
			res, err := Install(d, o)
			require.NoError(t, err)
			require.True(t, res.Changed())
			data, err := os.ReadFile(d.Layout(o.Env).MCP)
			require.NoError(t, err)
			if d.MCP.Format == FormatTOML {
				assert.Contains(t, string(data), `[mcp_servers."keylatch-docs.remote"]`)
				assert.Contains(t, string(data), `args = ["mcp", "proxy", "docs.remote", "--url", "https://mcp.example.test/api"]`)
			} else {
				root, err := merge.ParseJSON(data)
				require.NoError(t, err)
				servers, err := root.Child(d.MCP.Key)
				require.NoError(t, err)
				entry, exists := servers.Get("keylatch-docs.remote")
				require.True(t, exists)
				assert.True(t, runsMCPProxy(entry, testBinary))
			}
			again, err := Install(d, o)
			require.NoError(t, err)
			assert.False(t, again.Changed())
			_, err = Uninstall(d, o)
			require.NoError(t, err)
			data, err = os.ReadFile(d.Layout(o.Env).MCP)
			require.NoError(t, err)
			assert.NotContains(t, string(data), "keylatch-docs.remote")
		})
	}
}

func TestInvalidProxiesWriteNothing(t *testing.T) {
	for name, proxies := range map[string][]Proxy{
		"duplicate":    {{"docs", "https://example.test"}, {"docs", "https://other.test"}},
		"invalid name": {{"../docs", "https://example.test"}},
		"userinfo":     {{"docs", "https://user:password@example.test"}},
		"plain remote": {{"docs", "http://example.test"}},
		"missing host": {{"docs", "https:"}},
	} {
		t.Run(name, func(t *testing.T) {
			d, _ := harness.Lookup("gemini-cli")
			home := t.TempDir()
			_, err := Install(d, Options{Env: testEnv(home), Command: GuardCommand(d, testBinary), Server: Server{Command: testBinary}, Proxies: proxies})
			require.Error(t, err)
			assert.Empty(t, readTree(t, home))
		})
	}
}

func TestProxyUninstallPreservesLookalikeServers(t *testing.T) {
	d, _ := harness.Lookup("cursor")
	original := []byte(`{"mcpServers":{"keylatch":{"command":"/opt/keylatch/bin/keylatch","args":["mcp","--stdio"]},"keylatch-docs":{"command":"/opt/keylatch/bin/keylatch","args":["mcp","proxy","docs","--url","https://example.test"]},"keylatch-user":{"command":"/usr/bin/custom-server","args":["mcp","proxy","user","--url","https://example.test"]},"keylatch-log":{"command":"/usr/bin/logger","args":["keylatch","mcp","proxy","docs"]}}}`)
	data, err := removeMCP(d, original)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "keylatch-docs")
	assert.Contains(t, string(data), "keylatch-user")
	assert.Contains(t, string(data), "keylatch-log")
}
