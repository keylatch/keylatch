package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"encoding/pem"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type proxyFakeVault map[string][]byte

func (v proxyFakeVault) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	if b, ok := v[path]; ok {
		return b, backend.Meta{Path: path}, nil
	}
	return nil, backend.Meta{}, backend.ErrNotFound
}

type proxyAudit struct {
	mu sync.Mutex
	ev []audit.Event
}

func (a *proxyAudit) Emit(_ context.Context, e audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ev = append(a.ev, e)
	return nil
}

type recordingUpstream struct {
	mu   sync.Mutex
	auth []string
}

func (r *recordingUpstream) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.auth = append(r.auth, req.Header.Get("Authorization"))
	r.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
}

// proxyTestListen is the listener every test config entry describes.
const proxyTestListen = "10.0.2.2:7879"

func proxyTestConfig(repos []string, perms map[string]string) config.Config {
	return config.Config{Connections: map[string]config.ConnectionPolicy{"github-app": {
		Mint: &config.MintPolicy{GitHubApp: &config.GitHubAppMintPolicy{
			PermissionCeiling: map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read", "issues": "write", "actions": "read", "checks": "read"},
		}},
		Proxy: &config.ProxyPolicy{GitHub: []config.GitHubProxyPolicy{{Listen: proxyTestListen, Installations: []config.GitHubInstallationPolicy{{Owner: "octo", Repositories: repos, Permissions: perms}}}}},
	}}}
}

func TestProxyGitHubSettings(t *testing.T) {
	r, err := proxyGitHubSettings(proxyTestConfig([]string{"octo/a", "octo/b"}, nil), "github-app", proxyTestListen)
	require.NoError(t, err)
	require.Len(t, r.Installations, 1)
	in := r.Installations[0]
	assert.Equal(t, "octo", in.Owner)
	assert.Equal(t, []string{"octo/a", "octo/b"}, in.Repos)
	assert.Equal(t, defaultProxyGitHubPermissions, in.Perms)
	assert.Equal(t, "github.com", r.Host)

	// Any GitHub App permission name is accepted; the installation is the ceiling.
	r, err = proxyGitHubSettings(proxyTestConfig([]string{"octo/a"}, map[string]string{"contents": "read", "workflows": "write", "packages": "read", "issues": "write", "pages": "write"}), "github-app", proxyTestListen)
	require.NoError(t, err)
	assert.Equal(t, "write", r.Installations[0].Perms["workflows"])
	assert.Equal(t, "write", r.Installations[0].Policy.PermissionCeiling["pages"], "the installation's permissions are its ceiling")

	for name, perms := range map[string]map[string]string{
		"administration":     {"administration": "read"},
		"org administration": {"organization_administration": "read"},
		"members":            {"members": "read"},
		"admin level":        {"contents": "admin"},
		"bad level":          {"contents": "owner"},
		"bad name":           {"Contents": "read"},
		"bad name 2":         {"contents; drop": "read"},
	} {
		_, err := proxyGitHubSettings(proxyTestConfig([]string{"octo/a"}, perms), "github-app", proxyTestListen)
		assert.Error(t, err, name)
	}

	admin := proxyTestConfig([]string{"octo/a"}, map[string]string{"administration": "write", "contents": "admin"})
	admin.Connections["github-app"].Proxy.GitHub[0].Installations[0].AllowAdminPermissions = true
	_, err = proxyGitHubSettings(admin, "github-app", proxyTestListen)
	assert.NoError(t, err, "explicit opt-in per installation")

	for name, cfg := range map[string]config.Config{
		"repo of another owner": proxyTestConfig([]string{"octo/a", "other/b"}, nil),
		"bad repo":              proxyTestConfig([]string{"octo"}, nil),
		"no repos":              proxyTestConfig(nil, nil),
		"deny owner":            withDenyOwner(proxyTestConfig([]string{"octo/a"}, nil)),
		"no connection":         {},
	} {
		_, err := proxyGitHubSettings(cfg, "github-app", proxyTestListen)
		assert.Error(t, err, name)
	}
	noMint := proxyTestConfig([]string{"octo/a"}, nil)
	cp := noMint.Connections["github-app"]
	cp.Mint = nil
	noMint.Connections["github-app"] = cp
	_, err = proxyGitHubSettings(noMint, "github-app", proxyTestListen)
	assert.Error(t, err, "the proxy mints under the mint policy; without one it is denied")
}

func TestProxyGitHubSettings_Host(t *testing.T) {
	cfg := proxyTestConfig([]string{"octo/a"}, nil)
	cfg.Connections["github-app"].Proxy.GitHub[0].Host = "Octocorp.GHE.com"
	r, err := proxyGitHubSettings(cfg, "github-app", proxyTestListen)
	require.NoError(t, err)
	assert.Equal(t, "octocorp.ghe.com", r.Host)
	assert.Equal(t, []string{"octocorp.ghe.com"}, configuredProxyHosts(cfg))
	assert.Equal(t, []string{"github.com"}, configuredProxyHosts(proxyTestConfig([]string{"octo/a"}, nil)))
}

func loopbackProxyConfig(c config.Config) config.Config {
	c.Connections["github-app"].Proxy.GitHub[0].Listen = "127.0.0.1:17879"
	return c
}

func withDenyOwner(c config.Config) config.Config {
	cp := c.Connections["github-app"]
	cp.Mint.GitHubApp.DenyOwners = []string{"octo"}
	c.Connections["github-app"] = cp
	return c
}

func TestProxyGitHubSettings_RepositoriesFeedTheMintAllowlistNotTheReverse(t *testing.T) {
	// The mint policy names no repositories; the installation's list is the
	// allowlist for the proxy only, so another repo is still not minted by /mint/github.
	cfg := proxyTestConfig([]string{"octo/a"}, nil)
	r, err := proxyGitHubSettings(cfg, "github-app", proxyTestListen)
	require.NoError(t, err)
	assert.Equal(t, []string{"octo/a"}, r.Installations[0].Policy.AllowRepos)
	assert.Empty(t, cfg.Connections["github-app"].Mint.GitHubApp.AllowRepos, "the operator's mint policy is not modified")

	_, err = proxyGitHubSettings(cfg, "github-app", "10.0.2.2:9999")
	assert.Error(t, err, "a listener needs its own config entry")
}

func TestProxyGitHubSettings_TwoInstallationsOnOneListener(t *testing.T) {
	cfg := proxyTestConfig([]string{"octo/a"}, nil)
	cp := cfg.Connections["github-app"]
	cp.Proxy.GitHub[0].Installations = append(cp.Proxy.GitHub[0].Installations, config.GitHubInstallationPolicy{Owner: "Other", Repositories: []string{"other/x", "other/y"}, Permissions: map[string]string{"contents": "read"}})
	cfg.Connections["github-app"] = cp
	r, err := proxyGitHubSettings(cfg, "github-app", proxyTestListen)
	require.NoError(t, err)
	require.Len(t, r.Installations, 2)
	assert.Equal(t, []string{"octo/a"}, r.Installations[0].Repos)
	assert.Equal(t, "other", r.Installations[1].Owner)
	assert.Equal(t, map[string]string{"contents": "read"}, r.Installations[1].Perms, "each installation has its own permissions")

	cp.Proxy.GitHub[0].Installations = append(cp.Proxy.GitHub[0].Installations, config.GitHubInstallationPolicy{Owner: "OCTO", Repositories: []string{"octo/z"}})
	_, err = proxyGitHubSettings(cfg, "github-app", proxyTestListen)
	assert.Error(t, err, "an owner twice on one listener")
}

func TestParseProxyListeners(t *testing.T) {
	got, err := parseProxyListeners([]string{"10.0.2.2:7879=a", "10.0.2.2:7880=b"})
	require.NoError(t, err)
	assert.Equal(t, []proxyListener{{"10.0.2.2:7879", "a"}, {"10.0.2.2:7880", "b"}}, got)
	for _, bad := range [][]string{{"x"}, {"=a"}, {"1.1.1.1:1="}, {"1.1.1.1:1=a", "1.1.1.1:1=b"}} {
		_, err := parseProxyListeners(bad)
		assert.Error(t, err, "%v", bad)
	}
}

func TestEnsureProxyCallerToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gw", "proxy-token")
	a, err := ensureProxyCallerToken(path)
	require.NoError(t, err)
	assert.Len(t, a, 64)
	st, _ := os.Stat(path)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	b, err := ensureProxyCallerToken(path)
	require.NoError(t, err)
	assert.Equal(t, a, b, "stable across restarts")

	require.NoError(t, os.Chmod(path, 0o644))
	_, err = ensureProxyCallerToken(path)
	assert.Error(t, err)
	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.WriteFile(path, []byte("short"), 0o600))
	_, err = ensureProxyCallerToken(path)
	assert.Error(t, err)
}

func TestNewGitHubProxy_MintsOneMultiRepoTokenAndInjectsIt(t *testing.T) {
	require.NoError(t, registry.InitFromConfig(context.Background(), os.Getenv), "the github-app template must be loaded")
	t.Setenv("KEYLATCH_GATEWAY_DIR", filepath.Join(t.TempDir(), "gw"))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	rt, rerr := registry.Get("github-app")
	require.NoError(t, rerr)
	tmpl := rt.Category

	var mintBody map[string]any
	var mints int
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mints++
		_ = json.NewDecoder(r.Body).Decode(&mintBody)
		var repos []map[string]string
		for _, n := range mintBody["repositories"].([]any) {
			repos = append(repos, map[string]string{"full_name": "octo/" + n.(string)})
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_canary_token", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "permissions": mintBody["permissions"], "repositories": repos})
	}))
	defer gh.Close()

	vault := proxyFakeVault{
		"default/" + tmpl + "/github-app/config/app_id":            []byte("1"),
		"default/" + tmpl + "/github-app/config/installation_octo": []byte("42"),
		"default/" + tmpl + "/github-app/private_key":              keyPEM,
	}
	em := &proxyAudit{}
	up := &recordingUpstream{}
	srv, err := newGitHubProxy(gitHubProxyParams{
		Connection: "github-app", Listen: "127.0.0.1:17879", Lookup: llmcontext.DefaultLookup,
		Config: loopbackProxyConfig(proxyTestConfig([]string{"octo/a", "octo/b"}, nil)), Vault: vault, Audit: em,
		APIBase: gh.URL, Upstream: up,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"github.com", "api.github.com", "uploads.github.com"}, srv.Profile.Hosts)

	front := httptest.NewServer(http.HandlerFunc(srv.ServeHTTP))
	defer front.Close()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(srv.CA.CertPEM()))
	tokenFile, _ := os.ReadFile(proxyCallerTokenPath(llmcontext.DefaultLookup))
	pu, _ := url.Parse(front.URL)
	pu.User = url.UserPassword("octo", strings.TrimSpace(string(tokenFile)))
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}

	resp, err := c.Get("https://github.com/octo/a.git/info/refs?service=git-upload-pack")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)
	resp, err = c.Get("https://github.com/octo/zzz.git/info/refs?service=git-upload-pack")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode)

	assert.Equal(t, 1, mints)
	assert.ElementsMatch(t, []any{"a", "b"}, mintBody["repositories"])
	assert.Equal(t, map[string]any{"contents": "write", "pull_requests": "write", "metadata": "read"}, mintBody["permissions"])
	require.Len(t, up.auth, 1)
	assert.True(t, strings.HasPrefix(up.auth[0], "Basic "))

	em.mu.Lock()
	dump, _ := json.Marshal(em.ev)
	em.mu.Unlock()
	assert.Contains(t, string(dump), `"mint"`)
	assert.NotContains(t, string(dump), "ghs_canary_token")
}

func TestNewGitHubProxy_RefusesOpenBindAndBadInput(t *testing.T) {
	require.NoError(t, registry.InitFromConfig(context.Background(), os.Getenv), "the github-app template must be loaded")
	t.Setenv("KEYLATCH_GATEWAY_DIR", filepath.Join(t.TempDir(), "gw"))
	base := gitHubProxyParams{Connection: "github-app", Listen: "10.0.2.2:7879", Lookup: llmcontext.DefaultLookup, Config: proxyTestConfig([]string{"octo/a"}, nil), Vault: proxyFakeVault{}, Audit: &proxyAudit{}}

	_, err := newGitHubProxy(base)
	require.Error(t, err, "bridge address without --allow-source")
	assert.Contains(t, err.Error(), "allow-source")

	ok := base
	ok.AllowSources = []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")}
	srv, err := newGitHubProxy(ok)
	require.NoError(t, err)
	assert.True(t, srv.AllowNonLoopback)
	assert.False(t, srv.SourceAllowed("10.0.0.5:1234"))
	assert.True(t, srv.SourceAllowed("10.0.2.7:1234"))

	for _, bad := range []string{"0.0.0.0:7879", "host:7879", ":7879"} {
		p := ok
		p.Listen = bad
		_, err := newGitHubProxy(p)
		assert.Error(t, err, bad)
	}
	p := ok
	p.Connection = "openrouter"
	_, err = newGitHubProxy(p)
	assert.Error(t, err)
}

func TestProxyCAPrintHasNoKeyAndTokenPrintRefusesInLLMSession(t *testing.T) {
	home, _ := systemdTestEnv(t)
	cfg := proxyTestConfig([]string{"octo/a"}, nil)
	cfg.Version = 1
	require.NoError(t, config.Save(paths.DefaultConfig(home), cfg))
	cmd := newProxyCACmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"print"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "BEGIN CERTIFICATE")
	assert.NotContains(t, out.String(), "PRIVATE")
	key, err := os.ReadFile(proxyCAKeyPath(llmcontext.DefaultLookup))
	require.NoError(t, err)
	assert.NotContains(t, out.String(), strings.Split(string(key), "\n")[1])

	t.Setenv("CLAUDECODE", "1")
	tc := newProxyTokenCmd()
	tc.SetArgs([]string{"print"})
	tc.SetOut(&out)
	tc.SetErr(&out)
	assert.Error(t, tc.Execute())
}
