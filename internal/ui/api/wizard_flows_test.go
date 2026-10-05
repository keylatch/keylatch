package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mxBackendsOnce sync.Once

// mxRegisterBackends registers placeholder factories so BackendsHandler has
// names to report; the factories are never invoked.
func mxRegisterBackends() {
	mxBackendsOnce.Do(func() {
		nop := func(context.Context, backend.BackendConfig) (backend.Backend, error) {
			return nil, errors.New("not used")
		}
		for _, name := range []string{"file", "op", "bw", "keeper", "lastpass", "vault", "zz-custom"} {
			_ = backend.Default.Register(name, nop)
		}
	})
}

func mxReadiness(t *testing.T, h *api.WizardHandlers) map[string]api.ReadinessCheck {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ReadinessHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/health/readiness", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var resp api.ReadinessResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	out := map[string]api.ReadinessCheck{"_status": {Name: resp.Status}}
	for _, c := range resp.Checks {
		out[c.Name] = c
	}
	return out
}

func TestBackendsHandler_AvailabilityFollowsPATH(t *testing.T) {
	mxRegisterBackends()
	dir := mxFakeBinDir(t, map[string]string{"bw": "exit 0\n"})
	t.Setenv("PATH", dir)

	rec := httptest.NewRecorder()
	(&api.WizardHandlers{}).BackendsHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/backends", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var items []api.BackendListItem
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&items))
	got := map[string]api.BackendListItem{}
	for _, it := range items {
		got[it.Name] = it
	}

	assert.True(t, got["file"].Available)
	assert.True(t, got["vault"].Available, "networked backends need no local binary")
	assert.True(t, got["bw"].Available, "bw is on PATH")
	assert.False(t, got["op"].Available, "op is not on PATH")
	assert.Equal(t, "Install: brew install 1password-cli", got["op"].InstallHint)
	assert.False(t, got["keeper"].Available)
	assert.False(t, got["lastpass"].Available, "lastpass is never detectable")
	assert.True(t, got["zz-custom"].Available, "unknown backends are assumed available")
	assert.Equal(t, "zz-custom", got["zz-custom"].DisplayName)
}

func TestBootstrapHandler(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("KEYLATCH_CONFIG_DIR", cfgDir)
	h := &api.WizardHandlers{}

	call := func(method, body string) (int, map[string]interface{}) {
		rec := httptest.NewRecorder()
		h.BootstrapHandler(rec, httptest.NewRequest(method, "/v1/bootstrap", strings.NewReader(body)))
		var out map[string]interface{}
		if rec.Code == http.StatusOK {
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
		}
		return rec.Code, out
	}

	code, _ := call(http.MethodGet, "")
	assert.Equal(t, http.StatusMethodNotAllowed, code)

	_, out := call(http.MethodPost, `{}`)
	assert.Equal(t, false, out["ok"])
	assert.Equal(t, "backend is required", out["error"])

	_, out = call(http.MethodPost, `{"backend":"no-such-backend"}`)
	assert.Equal(t, false, out["ok"])
	assert.Contains(t, out["error"], "unknown backend")

	_, out = call(http.MethodPost, `{"backend":"op"}`)
	require.Equal(t, true, out["ok"], out)
	assert.Equal(t, "op", out["backend"])
	info, err := os.Stat(cfgDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	entries, err := os.ReadDir(cfgDir)
	require.NoError(t, err)
	assert.NotEmpty(t, entries, "bootstrap must create files under the config dir")
}

type mxGetter struct {
	tmpl registry.ConnectionTemplate
	err  error
}

func (g mxGetter) Get(string) (registry.ConnectionTemplate, error) { return g.tmpl, g.err }

func TestProviderDetailHandler(t *testing.T) {
	t.Parallel()
	withFields := registry.ConnectionTemplate{
		Provider: "acme", DisplayName: "Acme", Category: "ai",
		SecretFields: []registry.SecretField{
			{Name: "token", Label: "Token", Required: true},
			{Name: "org_id"},
		},
	}
	cases := []struct {
		name   string
		getter api.ProviderGetter
		method string
		path   string
		want   int
	}{
		{"post rejected", mxGetter{tmpl: withFields}, http.MethodPost, "/v1/providers/acme", http.StatusMethodNotAllowed},
		{"empty slug", mxGetter{tmpl: withFields}, http.MethodGet, "/v1/providers/", http.StatusBadRequest},
		{"unknown slug", mxGetter{err: errors.New("nope")}, http.MethodGet, "/v1/providers/ghost", http.StatusNotFound},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		(&api.WizardHandlers{ProviderDetailSource: tc.getter}).ProviderDetailHandler(rec, httptest.NewRequest(tc.method, tc.path, nil))
		assert.Equal(t, tc.want, rec.Code, tc.name)
	}

	rec := httptest.NewRecorder()
	(&api.WizardHandlers{ProviderDetailSource: mxGetter{tmpl: withFields}}).ProviderDetailHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/providers/acme/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var detail api.ProviderDetailResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&detail))
	assert.Equal(t, api.ProviderDetailResponse{
		Slug: "acme", DisplayName: "Acme", Category: "ai",
		Fields: []api.SecretFieldItem{
			{Name: "token", Label: "Token", Required: true},
			{Name: "org_id", Label: "org_id"},
		},
	}, detail)

	rec = httptest.NewRecorder()
	(&api.WizardHandlers{ProviderDetailSource: mxGetter{tmpl: registry.ConnectionTemplate{Provider: "bare"}}}).ProviderDetailHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/providers/bare", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	detail = api.ProviderDetailResponse{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&detail))
	assert.Equal(t, []api.SecretFieldItem{{Name: "api_key", Label: "API Key", Required: true}}, detail.Fields)
}

func TestProviderDetailHandler_DefaultRegistry(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	rec := httptest.NewRecorder()
	(&api.WizardHandlers{}).ProviderDetailHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/providers/openrouter", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var detail api.ProviderDetailResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&detail))
	assert.Equal(t, "openrouter", detail.Slug)
	assert.NotEmpty(t, detail.Fields)

	rec = httptest.NewRecorder()
	(&api.WizardHandlers{}).ProviderDetailHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/providers/definitely-not-a-provider", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestProvidersHandler_DocsAndModeFallbacks(t *testing.T) {
	t.Parallel()
	tmpl := registry.ConnectionTemplate{Provider: "acme", DisplayName: "Acme", Category: "ai"}
	tmpl.Docs.CredentialsURL = "https://example.invalid/keys"
	tmpl.RuntimeSupport.Preferred = registry.RuntimeMode("gateway_typed")
	rec := httptest.NewRecorder()
	(&api.WizardHandlers{ProviderSource: &stubProviderLister{templates: []registry.ConnectionTemplate{tmpl}}}).ProvidersHandler(rec, httptest.NewRequest(http.MethodGet, "/v1/providers", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var items []api.ProviderListItem
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&items))
	require.Len(t, items, 1)
	assert.Equal(t, "https://example.invalid/keys", items[0].DocsURL)
	assert.Equal(t, []string{"gateway_typed"}, items[0].RuntimeModes)
}

func TestConnectHandler_WithStore(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	post := func(h *api.WizardHandlers, body string) (int, map[string]interface{}) {
		rec := httptest.NewRecorder()
		h.ConnectHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/connect", bytes.NewBufferString(body)))
		var out map[string]interface{}
		if rec.Code == http.StatusOK {
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
		}
		return rec.Code, out
	}
	key := "wizard-" + strings.Repeat("k", 12)
	store := newAPIMemoryStore()
	h := &api.WizardHandlers{Store: store}

	code, out := post(h, `{"provider":"openrouter","api_key":"`+key+`","backend":"file"}`)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, true, out["ok"])
	v, _, err := store.Get(context.Background(), "default/ai/openrouter/api_key")
	require.NoError(t, err)
	assert.Equal(t, key, string(v))

	// Re-running the wizard for an existing connection is not an error.
	_, out = post(h, `{"provider":"openrouter","api_key":"`+key+`","backend":"file"}`)
	assert.Equal(t, true, out["ok"])

	_, out = post(h, `{"provider":"no-such-provider-xyz","api_key":"`+key+`","backend":"file"}`)
	assert.Equal(t, false, out["ok"])
	assert.Equal(t, "unknown provider: no-such-provider-xyz", out["error"])

	failing := &api.WizardHandlers{Store: &mxFlakyStore{apiMemoryStore: newAPIMemoryStore(), failSet: func(string) bool { return true }}}
	_, out = post(failing, `{"provider":"openrouter","api_key":"`+key+`","backend":"file"}`)
	assert.Equal(t, false, out["ok"])
	assert.Equal(t, "internal error", out["error"], "internal errors must not leak details")

	code, _ = post(h, `{"api_key": 12}`)
	assert.Equal(t, http.StatusBadRequest, code)
	code, _ = post(h, `{bad`)
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestAgentSetupHandler_CustomGatewayAndBadBody(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{GatewayAddr: "127.0.0.1:9999"}
	rec := httptest.NewRecorder()
	h.AgentSetupHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/agent/setup", strings.NewReader(`{"agent":"codex"}`)))
	require.Equal(t, http.StatusOK, rec.Code)
	var out map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	assert.Contains(t, out["snippet"], "for codex")
	assert.Contains(t, out["snippet"], "http://127.0.0.1:9999")

	rec = httptest.NewRecorder()
	h.AgentSetupHandler(rec, httptest.NewRequest(http.MethodPost, "/v1/agent/setup", strings.NewReader(`{`)))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestReadiness_AllGreen(t *testing.T) {
	mxRegisterBackends()
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".codex"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, ".codex", "config.json"), []byte("{}"), 0o600))

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer gw.Close()

	pidPath := filepath.Join(t.TempDir(), "gateway.pid")
	require.NoError(t, os.WriteFile(pidPath, []byte("4242\n"), 0o600))

	store := &stubStore{entries: []backend.Entry{{Meta: backend.Meta{Path: "default/ai/openai/meta"}}}}
	checks := mxReadiness(t, &api.WizardHandlers{
		Store:          store,
		GatewayPIDPath: pidPath,
		GatewayAddr:    strings.TrimPrefix(gw.URL, "http://"),
	})
	for _, name := range []string{"backend_configured", "provider_connected", "agent_configured", "gateway_healthy", "canary_pass"} {
		assert.True(t, checks[name].OK, "%s: %s", name, checks[name].Message)
	}
	assert.Equal(t, "green", checks["_status"].Name)
}

func TestReadiness_FailureMessages(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer gw.Close()
	addr := strings.TrimPrefix(gw.URL, "http://")

	dir := t.TempDir()
	emptyPID := filepath.Join(dir, "empty.pid")
	require.NoError(t, os.WriteFile(emptyPID, []byte("  \n"), 0o600))

	checks := mxReadiness(t, &api.WizardHandlers{
		Store:          &stubStore{listErr: errors.New("boom")},
		GatewayPIDPath: filepath.Join(dir, "missing.pid"),
		GatewayAddr:    addr,
	})
	assert.False(t, checks["provider_connected"].OK)
	assert.False(t, checks["agent_configured"].OK)
	assert.Contains(t, checks["agent_configured"].Message, "no agent config file found")
	assert.Equal(t, "gateway not running: PID file missing", checks["gateway_healthy"].Message)
	assert.False(t, checks["canary_pass"].OK)
	assert.Contains(t, checks["canary_pass"].Message, "503")
	assert.Equal(t, "red", checks["_status"].Name)

	checks = mxReadiness(t, &api.WizardHandlers{GatewayPIDPath: emptyPID, GatewayAddr: addr})
	assert.Equal(t, "gateway not running: PID file empty", checks["gateway_healthy"].Message)

	// No gateway configured: health is false but canary is skipped as non-fatal.
	checks = mxReadiness(t, &api.WizardHandlers{})
	assert.Equal(t, "gateway PID path not configured", checks["gateway_healthy"].Message)
	assert.True(t, checks["canary_pass"].OK)
	assert.Contains(t, checks["canary_pass"].Message, "skipped")

	// Unreachable gateway address.
	closed := httptest.NewServer(http.NotFoundHandler())
	closedAddr := strings.TrimPrefix(closed.URL, "http://")
	closed.Close()
	checks = mxReadiness(t, &api.WizardHandlers{GatewayPIDPath: emptyPID, GatewayAddr: closedAddr})
	assert.False(t, checks["canary_pass"].OK)
	assert.Contains(t, checks["canary_pass"].Message, "canary probe failed")
}
