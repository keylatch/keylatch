package placeholder

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/templates/providers"
)

func registryTemplate(t *testing.T, name string) registry.ConnectionTemplate {
	t.Helper()
	data, err := providers.EmbeddedFS.ReadFile("saas/packages/" + name + ".yaml")
	require.NoError(t, err)
	require.NoError(t, registry.ValidateTemplateBytes(data))
	var tmpl registry.ConnectionTemplate
	require.NoError(t, yaml.Unmarshal(data, &tmpl))
	return tmpl
}

func TestRegistryPublishSlots(t *testing.T) {
	const secret = "stored-registry-credential-0123456789"
	for _, tc := range []struct{ name, method, url string }{
		{"npm", "PUT", "https://registry.npmjs.org/package"},
		{"pypi", "POST", "https://upload.pypi.org/legacy/"},
		{"cargo", "PUT", "https://crates.io/api/v1/crates/new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := registryTemplate(t, tc.name)
			res := &staticResolver{vals: map[string]string{"token": secret}}
			h := newHarness(t, func(cfg *Config, req *OpenRequest) { cfg.Resolver = res; req.Template = tmpl })
			ph := h.sess.Placeholders()["token"]
			require.NotEmpty(t, ph)
			assert.NotEqual(t, secret, ph)
			auth := ph
			switch tc.name {
			case "npm":
				auth = "Bearer " + ph
			case "pypi":
				auth = "Basic " + base64.StdEncoding.EncodeToString([]byte("__token__:"+ph))
			}
			resp, _ := h.do(h.client(false), tc.method, tc.url, strings.NewReader("package contents"), map[string]string{"Authorization": auth})
			require.Equal(t, http.StatusOK, resp.StatusCode)
			requests := h.up.requests()
			require.Len(t, requests, 1)
			want := secret
			switch tc.name {
			case "npm":
				want = "Bearer " + secret
			case "pypi":
				want = "Basic " + base64.StdEncoding.EncodeToString([]byte("__token__:"+secret))
			}
			assert.Equal(t, want, requests[0].Header.Get("Authorization"))
			assert.NotContains(t, h.audit.dump(), secret)
			assert.NotContains(t, h.audit.dump(), ph)
			resp, _ = h.do(h.client(false), tc.method, tc.url+"?token="+ph, nil, nil)
			assert.NotEqual(t, http.StatusOK, resp.StatusCode)
			require.Len(t, h.up.requests(), 1, "a token outside its credential slot must not reach the registry")
			c := h.client(false)
			r, err := http.NewRequest(tc.method, "https://other.stripe.com/", nil)
			require.NoError(t, err)
			r.Header.Set("Authorization", auth)
			response, err := c.Do(r)
			if response != nil {
				_ = response.Body.Close()
				assert.NotEqual(t, http.StatusOK, response.StatusCode)
			}
			assert.Error(t, err, "an unbound CONNECT target must be refused")
			require.Len(t, h.up.requests(), 1)
			if tc.name == "cargo" {
				r, err := http.NewRequest("GET", "https://index.crates.io/config.json", nil)
				require.NoError(t, err)
				r.Header.Set("Authorization", ph)
				resp, err := h.client(false).Do(r)
				if resp != nil {
					_ = resp.Body.Close()
					assert.NotEqual(t, http.StatusOK, resp.StatusCode)
				} else {
					assert.Error(t, err)
				}
				require.Len(t, h.up.requests(), 1, "download hosts have no credential slot")
			}
		})
	}
}

func TestNPMClientAuthenticatesWithOnlyPlaceholder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("npm process conformance requires the Linux D3 runtime")
	}
	npm, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm is required for registry client conformance")
	}
	const secret = "stored-npm-credential-0123456789"
	h := newHarness(t, func(cfg *Config, req *OpenRequest) {
		cfg.Resolver = &staticResolver{vals: map[string]string{"token": secret}}
		req.Template = registryTemplate(t, "npm")
	})
	h.up.mu.Lock()
	h.up.fn = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"username":"registry-conformance"}`)
	}
	h.up.mu.Unlock()
	dir := t.TempDir()
	ca, config := filepath.Join(dir, "ca.pem"), filepath.Join(dir, ".npmrc")
	require.NoError(t, os.WriteFile(ca, h.sess.CAPEM(), 0o600))
	require.NoError(t, os.WriteFile(config, []byte("//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nhttps-proxy=http://"+h.ln.Addr().String()+"\ncafile="+ca+"\n"), 0o600))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, npm, "--userconfig", config, "whoami", "--registry", "https://registry.npmjs.org")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "NPM_TOKEN=" + h.sess.Placeholders()["token"], "NODE_EXTRA_CA_CERTS=" + ca, "NPM_CONFIG_UPDATE_NOTIFIER=false"}
	for _, entry := range cmd.Env {
		assert.NotContains(t, entry, secret)
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, "registry-conformance", strings.TrimSpace(string(out)))
	requests := h.up.requests()
	require.Len(t, requests, 1)
	assert.Equal(t, "Bearer "+secret, requests[0].Header.Get("Authorization"))
}
