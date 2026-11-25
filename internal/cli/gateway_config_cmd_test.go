package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runGatewayConfig(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newGatewayConfigCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func loadOperatorCfg(t *testing.T, home string) config.Config {
	t.Helper()
	cfg, err := config.Load(paths.DefaultConfig(home))
	require.NoError(t, err)
	return cfg
}

func TestGatewayConfig_SetValidatesAndPersists(t *testing.T) {
	home, _ := systemdTestEnv(t)

	out, err := runGatewayConfig(t, "set", "--listen", "10.0.2.2:7878", "--allow-source", "10.0.2.9/24", "--github-mint", "github-app")
	require.NoError(t, err)
	assert.Contains(t, out, "restart")
	svc := loadOperatorCfg(t, home).Gateway.Service
	assert.Equal(t, "10.0.2.2:7878", svc.Listen)
	assert.Equal(t, []string{"10.0.2.0/24"}, svc.AllowSource, "canonical CIDR")

	// Only the flags given change.
	_, err = runGatewayConfig(t, "set", "--github-mint", "other")
	require.NoError(t, err)
	svc = loadOperatorCfg(t, home).Gateway.Service
	assert.Equal(t, "other", svc.GitHubMint)
	assert.Equal(t, "10.0.2.2:7878", svc.Listen)

	for _, bad := range [][]string{
		{"--listen", "0.0.0.0:7878"}, {"--listen", "host:7878"}, {"--allow-source", "nope"},
		{"--github-mint", "a b"}, {"--allow-any-source", "--allow-source", "10.0.2.0/24"},
	} {
		_, err := runGatewayConfig(t, append([]string{"set"}, bad...)...)
		assert.Error(t, err, "%v", bad)
	}
	assert.Equal(t, "10.0.2.2:7878", loadOperatorCfg(t, home).Gateway.Service.Listen, "a refused set changes nothing")

	_, err = runGatewayConfig(t, "set", "--allow-source", "", "--allow-any-source=false")
	assert.Error(t, err, "clearing the sources of a non-loopback listen is refused")
	_, err = runGatewayConfig(t, "set", "--listen", "", "--allow-source", "", "--github-mint", "")
	require.NoError(t, err)
	assert.Nil(t, loadOperatorCfg(t, home).Gateway.Service, "everything cleared removes the section")
}

func TestGatewayConfig_AddAndRemoveProxy(t *testing.T) {
	home, _ := systemdTestEnv(t)
	add := func(args ...string) (string, error) {
		return runGatewayConfig(t, append([]string{"add-proxy", "--connection", "github-app", "--listen", "10.0.2.2:7879"}, args...)...)
	}

	_, err := add("--owner", "Octo", "--repo", "app", "--repo", "octo/tools")
	require.NoError(t, err)
	_, err = add("--owner", "other", "--repo", "service", "--permission", "contents=read", "--permission", "workflows=write")
	require.NoError(t, err)
	_, err = add("--owner", "octo", "--repo", "app")
	require.NoError(t, err, "same owner replaces its installation")

	cfg := loadOperatorCfg(t, home)
	cp := cfg.Connections["github-app"]
	require.NotNil(t, cp.Mint.GitHubApp, "an empty mint policy is created")
	require.Len(t, cp.Proxy.GitHub, 1)
	l := cp.Proxy.GitHub[0]
	require.Len(t, l.Installations, 2, "two owners share one listener")
	byOwner := map[string]config.GitHubInstallationPolicy{}
	for _, i := range l.Installations {
		byOwner[strings.ToLower(i.Owner)] = i
	}
	assert.Equal(t, []string{"octo/app"}, byOwner["octo"].Repositories)
	assert.Equal(t, []string{"other/service"}, byOwner["other"].Repositories)
	assert.Equal(t, "write", byOwner["other"].Permissions["workflows"])

	out, err := runGatewayConfig(t, "get", "--json")
	require.NoError(t, err)
	var info gatewayInfo
	require.NoError(t, json.Unmarshal([]byte(out), &info))
	require.Len(t, info.Proxies, 1)
	assert.Len(t, info.Proxies[0].Installations, 2)

	for name, args := range map[string][]string{
		"admin without opt-in":  {"--owner", "x", "--repo", "r", "--permission", "administration=write"},
		"repo of another owner": {"--owner", "x", "--repo", "y/r"},
		"bad permission":        {"--owner", "x", "--repo", "r", "--permission", "contents=owner"},
		"bad owner":             {"--owner", "x/y", "--repo", "r"},
	} {
		_, err := add(args...)
		assert.Error(t, err, name)
	}
	_, err = add("--owner", "x", "--repo", "r", "--permission", "administration=write", "--allow-admin-permissions")
	assert.NoError(t, err)

	_, err = runGatewayConfig(t, "remove-proxy", "--listen", "10.0.2.2:7879", "--owner", "x")
	require.NoError(t, err)
	_, err = runGatewayConfig(t, "remove-proxy", "--listen", "10.0.2.2:7879", "--owner", "nobody")
	assert.Error(t, err)
	_, err = runGatewayConfig(t, "remove-proxy", "--listen", "10.0.2.2:7879")
	require.NoError(t, err)
	assert.Nil(t, loadOperatorCfg(t, home).Connections["github-app"].Proxy, "the listener is gone")
	_, err = runGatewayConfig(t, "remove-proxy", "--listen", "10.0.2.2:7879")
	assert.Error(t, err)
}

func TestGatewayConfig_ListenerCannotShareTheGatewayAddress(t *testing.T) {
	systemdTestEnv(t)
	_, err := runGatewayConfig(t, "set", "--listen", "127.0.0.1:7878")
	require.NoError(t, err)
	_, err = runGatewayConfig(t, "add-proxy", "--connection", "github-app", "--listen", "127.0.0.1:7878", "--owner", "octo", "--repo", "a")
	assert.Error(t, err)
}

func TestGatewayInfo_ValueFreeAndFingerprintsTheCA(t *testing.T) {
	home, _ := systemdTestEnv(t)
	cfg := proxyTestConfig([]string{"octo/a"}, nil)
	cfg.Version = 1
	cfg.Gateway = &config.GatewayConfig{Service: &config.GatewayServiceConfig{Listen: "10.0.2.2:7878", AllowSource: []string{"10.0.2.0/24"}, GitHubMint: "github-app"}}
	require.NoError(t, config.Save(paths.DefaultConfig(home), cfg))

	// A CA, a caller token, a sealed credential and a vault ref exist on disk; none may leak.
	lookup := func(k string) string { return os.Getenv(k) }
	ca, err := loadProxyCA(lookup, []string{"github.com"})
	require.NoError(t, err)
	token, err := ensureProxyCallerToken(proxyCallerTokenPath(lookup))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(home, "gw", "op-sa.cred"), []byte("sealed-credential-bytes"), 0o600))
	keyPEM, _ := os.ReadFile(proxyCAKeyPath(lookup))

	out, err := runGatewayConfig(t, "get", "--json")
	require.NoError(t, err)
	var info gatewayInfo
	require.NoError(t, json.Unmarshal([]byte(out), &info))
	assert.Equal(t, "10.0.2.2:7878", info.Listen)
	assert.Equal(t, []string{"10.0.2.0/24"}, info.AllowSource)
	assert.Equal(t, "github-app", info.GitHubMint)
	require.Len(t, info.Proxies, 1)
	assert.Equal(t, "octo", info.Proxies[0].Installations[0].Owner)
	assert.Equal(t, 1, info.Schema)

	require.NotNil(t, info.CA)
	block, _ := pem.Decode([]byte(info.CA.PEM))
	require.NotNil(t, block)
	sum := sha256.Sum256(block.Bytes)
	assert.Equal(t, hex.EncodeToString(sum[:]), info.CA.SHA256)
	assert.Equal(t, string(ca.CertPEM()), info.CA.PEM)

	keyBody := strings.Split(string(keyPEM), "\n")[1]
	for _, secret := range []string{token, "PRIVATE", keyBody, "proxy-ca.key", "proxy-token", "kek.cred", "op-sa", "sealed-credential", "op://", home, "ghs_", "x-access-token"} {
		assert.NotContains(t, out, secret, "info must not contain %q", secret)
	}
}

func TestGatewayInfo_OmitsInvalidListenersAndMissingCA(t *testing.T) {
	home, _ := systemdTestEnv(t)
	cfg := proxyTestConfig([]string{"other/a"}, nil) // belongs to another owner than the installation
	cfg.Version = 1
	require.NoError(t, config.Save(paths.DefaultConfig(home), cfg))
	out, err := runGatewayConfig(t, "get", "--json")
	require.NoError(t, err)
	var info gatewayInfo
	require.NoError(t, json.Unmarshal([]byte(out), &info))
	assert.Empty(t, info.Proxies)
	assert.Nil(t, info.CA)
	text, err := runGatewayConfig(t, "get")
	require.NoError(t, err)
	assert.Contains(t, text, "invalid proxy entries")
}

func TestGatewayStatusJSON(t *testing.T) {
	home, _ := systemdTestEnv(t)
	cfg := config.Default()
	cfg.Gateway = &config.GatewayConfig{Service: &config.GatewayServiceConfig{Listen: "127.0.0.1:7878"}}
	require.NoError(t, config.Save(paths.DefaultConfig(home), cfg))
	cmd := newGatewayStatusCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--json"})
	require.NoError(t, cmd.Execute())
	var info gatewayInfo
	require.NoError(t, json.Unmarshal(out.Bytes(), &info))
	assert.Equal(t, "127.0.0.1:7878", info.Listen)
	assert.NotNil(t, info.Proxies, "an empty list, not null")
}

func TestGatewayLaunchd_UnitHoldsNoSettings(t *testing.T) {
	home, binary := systemdTestEnv(t)
	f := gatewayServiceFlags{binary: binary, backendCred: []string{"op-sa=OP_SERVICE_ACCOUNT_TOKEN"}}
	spec, err := f.launchdSpec(home)
	require.NoError(t, err)
	plist := spec.render()
	assert.Contains(t, plist, "<string>"+binary+"</string>")
	assert.Contains(t, plist, "<string>gateway</string>")
	assert.Contains(t, plist, "<string>--backend-credential</string>")
	assert.Contains(t, plist, "<string>op-sa=OP_SERVICE_ACCOUNT_TOKEN</string>")
	for _, absent := range []string{"KEYLATCH_GATEWAY_LISTEN", "--allow-source", "--github-mint", "--listen", "10.0.2"} {
		assert.NotContains(t, plist, absent)
	}
	assert.Contains(t, plist, "<key>RunAtLoad</key><true/>")

	f.backendCred = []string{"x=LD_PRELOAD"}
	_, err = f.launchdSpec(home)
	assert.Error(t, err)
}

func TestKeychainSecret_ReadsViaSecurityTool(t *testing.T) {
	r := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		"/usr/bin/security|find-generic-password|-s|keylatch-backend|-a|op-sa|-w": {Stdout: []byte("ops_secret\n")},
	}}
	origRunner, origResolve := opSARunner, resolveBinFunc
	opSARunner, resolveBinFunc = r, func(string) string { return "/usr/bin/security" }
	t.Cleanup(func() { opSARunner, resolveBinFunc = origRunner, origResolve })

	tok, err := keychainSecret("op-sa")
	require.NoError(t, err)
	assert.Equal(t, "ops_secret", tok)
	_, err = keychainSecret("missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "security add-generic-password")
	assert.NotContains(t, err.Error(), "ops_secret")
}
