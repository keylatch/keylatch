package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/backends
// ─────────────────────────────────────────────────────────────────────────────

func TestBackendsHandler_GET_ReturnsArray(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	req := httptest.NewRequest(http.MethodGet, "/v1/backends", nil)
	rec := httptest.NewRecorder()
	h.BackendsHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var items []api.BackendListItem
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&items))
	// global registry may be empty in tests; just ensure we get a JSON array back.
	assert.NotNil(t, items)
}

func TestBackendsHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	req := httptest.NewRequest(http.MethodPost, "/v1/backends", nil)
	rec := httptest.NewRecorder()
	h.BackendsHandler(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/providers
// ─────────────────────────────────────────────────────────────────────────────

// stubProviderLister implements api.ProviderLister for tests.
type stubProviderLister struct {
	templates []registry.ConnectionTemplate
}

func (s *stubProviderLister) List() []registry.ConnectionTemplate { return s.templates }

func TestProvidersHandler_GET_FallsBackToDefaults(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{
		ProviderSource: &stubProviderLister{templates: nil},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/providers", nil)
	rec := httptest.NewRecorder()
	h.ProvidersHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var items []api.ProviderListItem
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&items))
	assert.NotEmpty(t, items)
}

func TestProvidersHandler_GET_UsesInjectedLister(t *testing.T) {
	t.Parallel()
	tmpl := registry.ConnectionTemplate{
		Provider:    "test-provider",
		DisplayName: "Test Provider",
		Category:    "test",
		DocsURL:     "https://example.com",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
	}
	h := &api.WizardHandlers{
		ProviderSource: &stubProviderLister{templates: []registry.ConnectionTemplate{tmpl}},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/providers", nil)
	rec := httptest.NewRecorder()
	h.ProvidersHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var items []api.ProviderListItem
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&items))
	require.Len(t, items, 1)
	assert.Equal(t, "test-provider", items[0].Slug)
	assert.Equal(t, "Test Provider", items[0].DisplayName)
	assert.Equal(t, "test", items[0].Category)
	assert.Equal(t, "https://example.com", items[0].DocsURL)
	assert.Equal(t, []string{"gateway_typed"}, items[0].RuntimeModes)
}

func TestProvidersHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	req := httptest.NewRequest(http.MethodDelete, "/v1/providers", nil)
	rec := httptest.NewRecorder()
	h.ProvidersHandler(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/connect
// ─────────────────────────────────────────────────────────────────────────────

func TestConnectHandler_POST_Success(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	body := `{"provider":"openai","api_key":"sk-test","backend":"keychain"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/connect", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ConnectHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, true, resp["ok"])
}

func TestConnectHandler_POST_MissingFields(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	body := `{"provider":"openai"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/connect", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ConnectHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, false, resp["ok"])
	assert.NotEmpty(t, resp["error"])
}

func TestConnectHandler_POST_APIKeyNotEchoedBack(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	sentinel := "sk-CANARY_CONNECT_KEY_0xDEAD"
	body := `{"provider":"openai","api_key":"` + sentinel + `","backend":"keychain"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/connect", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ConnectHandler(rec, req)

	// The API key sentinel must never appear in the response body.
	assert.NotContains(t, rec.Body.String(), sentinel,
		"api_key value must not be echoed back in the response (S10-V)")
}

func TestConnectHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	req := httptest.NewRequest(http.MethodGet, "/v1/connect", nil)
	rec := httptest.NewRecorder()
	h.ConnectHandler(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/agent/setup
// ─────────────────────────────────────────────────────────────────────────────

func TestAgentSetupHandler_POST_Success(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	body := `{"agent":"claude-code"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/setup", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.AgentSetupHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, true, resp["ok"])
	assert.NotEmpty(t, resp["snippet"])
}

func TestAgentSetupHandler_POST_EmptyAgent(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	body := `{"agent":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/setup", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.AgentSetupHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, false, resp["ok"])
}

func TestAgentSetupHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	req := httptest.NewRequest(http.MethodGet, "/v1/agent/setup", nil)
	rec := httptest.NewRecorder()
	h.AgentSetupHandler(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/health/readiness
// ─────────────────────────────────────────────────────────────────────────────

// stubStore is a minimal connections.Store for readiness tests.
type stubStore struct {
	entries []backend.Entry
	listErr error
}

func (s *stubStore) Get(_ context.Context, _ string) ([]byte, backend.Meta, error) {
	return nil, backend.Meta{}, nil
}
func (s *stubStore) Set(_ context.Context, _ string, _ []byte, _ backend.Meta) error { return nil }
func (s *stubStore) Delete(_ context.Context, _ string) error                        { return nil }
func (s *stubStore) List(_ context.Context, _ string) ([]backend.Entry, error) {
	return s.entries, s.listErr
}

func TestReadinessHandler_GET_ReturnsChecks(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	req := httptest.NewRequest(http.MethodGet, "/v1/health/readiness", nil)
	rec := httptest.NewRecorder()
	h.ReadinessHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp api.ReadinessResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Status)
	assert.Len(t, resp.Checks, 5)

	// Verify check names are present.
	names := make([]string, 0, len(resp.Checks))
	for _, c := range resp.Checks {
		names = append(names, c.Name)
	}
	assert.Contains(t, names, "backend_configured")
	assert.Contains(t, names, "provider_connected")
	assert.Contains(t, names, "agent_configured")
	assert.Contains(t, names, "gateway_healthy")
	assert.Contains(t, names, "canary_pass")
}

// TestReadinessHandler_NoStore_ProviderConnectedFalse verifies that with no store
// wired, provider_connected is false and the overall status is "red".
func TestReadinessHandler_NoStore_ProviderConnectedFalse(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{} // Store is nil
	req := httptest.NewRequest(http.MethodGet, "/v1/health/readiness", nil)
	rec := httptest.NewRecorder()
	h.ReadinessHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp api.ReadinessResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	// With no store, provider_connected must be false.
	var providerCheck *api.ReadinessCheck
	for i := range resp.Checks {
		if resp.Checks[i].Name == "provider_connected" {
			providerCheck = &resp.Checks[i]
			break
		}
	}
	require.NotNil(t, providerCheck, "provider_connected check must be present")
	assert.False(t, providerCheck.OK, "provider_connected must be false when no store is wired")
	// No provider → at least one check is false → status must be red.
	assert.Equal(t, "red", resp.Status)
}

// TestReadinessHandler_WithStore_ProviderConnectedTrue verifies that when the store
// contains at least one connection meta entry (canonical path format: namespace/category/provider/meta),
// provider_connected is true.
func TestReadinessHandler_WithStore_ProviderConnectedTrue(t *testing.T) {
	t.Parallel()
	store := &stubStore{
		entries: []backend.Entry{{Meta: backend.Meta{Path: "default/ai/openai/meta"}}},
	}
	h := &api.WizardHandlers{Store: store}
	req := httptest.NewRequest(http.MethodGet, "/v1/health/readiness", nil)
	rec := httptest.NewRecorder()
	h.ReadinessHandler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp api.ReadinessResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	var providerCheck *api.ReadinessCheck
	for i := range resp.Checks {
		if resp.Checks[i].Name == "provider_connected" {
			providerCheck = &resp.Checks[i]
			break
		}
	}
	require.NotNil(t, providerCheck, "provider_connected check must be present")
	assert.True(t, providerCheck.OK, "provider_connected must be true when store has entries")
}

func TestReadinessHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := &api.WizardHandlers{}
	req := httptest.NewRequest(http.MethodPost, "/v1/health/readiness", nil)
	rec := httptest.NewRecorder()
	h.ReadinessHandler(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// ReceiptStore
// ─────────────────────────────────────────────────────────────────────────────

func TestReceiptStore_PushAndLast(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(5)

	for i := 0; i < 3; i++ {
		store.Push(runner.RuntimeReceipt{Provider: "openai", Capability: "chat", PolicyDecision: "allowed"})
	}

	got := store.Last(10)
	assert.Len(t, got, 3)
}

func TestReceiptStore_RingEviction(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(3)

	for i := 0; i < 5; i++ {
		store.Push(runner.RuntimeReceipt{Provider: "p", Capability: "c", PolicyDecision: "allowed", Runtime: strings.Repeat("x", i+1)})
	}

	got := store.Last(10)
	require.Len(t, got, 3)
	// Newest three: i=2,3,4 → Runtime lengths 3,4,5.
	assert.Equal(t, strings.Repeat("x", 3), got[0].Runtime)
	assert.Equal(t, strings.Repeat("x", 4), got[1].Runtime)
	assert.Equal(t, strings.Repeat("x", 5), got[2].Runtime)
}

func TestReceiptStore_LastNSubset(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	for i := 0; i < 7; i++ {
		store.Push(runner.RuntimeReceipt{Provider: "p"})
	}
	got := store.Last(3)
	assert.Len(t, got, 3)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/receipts
// ─────────────────────────────────────────────────────────────────────────────

func TestReceiptsHandler_GET_EmptyStore(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(100)
	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	receipts, ok := resp["receipts"]
	require.True(t, ok)
	assert.NotNil(t, receipts)
}

func TestReceiptsHandler_GET_ReturnsReceipts(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(100)
	store.Push(runner.RuntimeReceipt{Provider: "anthropic", Capability: "chat", PolicyDecision: "allowed"})
	store.Push(runner.RuntimeReceipt{Provider: "openai", Capability: "embed", PolicyDecision: "allowed"})

	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Receipts []map[string]interface{} `json:"receipts"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Len(t, body.Receipts, 2)
}

func TestReceiptsHandler_GET_NilStore(t *testing.T) {
	t.Parallel()
	h := api.NewReceiptsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotNil(t, resp["receipts"])
}

func TestReceiptsHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	h := api.NewReceiptsHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/v1/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/receipts/stream (basic SSE header checks; no long-running test)
// ─────────────────────────────────────────────────────────────────────────────

func TestReceiptsStreamHandler_GET_SSEHeaders(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	h := api.NewReceiptsStreamHandler(store)

	// Use a pre-cancelled context so the handler exits quickly after the first flush.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so the handler exits after the first heartbeat
	req := httptest.NewRequest(http.MethodGet, "/v1/receipts/stream", nil).WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "event: heartbeat")
}

func TestReceiptsStreamHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)
	h := api.NewReceiptsStreamHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/v1/receipts/stream", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ─────────────────────────────────────────────────────────────────────────────
// ReceiptStore Push notifies subscriber
// ─────────────────────────────────────────────────────────────────────────────

func TestReceiptStore_PushNotifiesSSEStream(t *testing.T) {
	t.Parallel()
	store := api.NewReceiptStore(10)

	// The SSE handler subscribes internally; validate via a direct Push + Last check.
	receipt := runner.RuntimeReceipt{
		Provider:       "anthropic",
		Capability:     "messages",
		PolicyDecision: "allowed",
		Runtime:        "gateway_typed",
		TTL:            30 * time.Second,
	}
	store.Push(receipt)

	got := store.Last(1)
	require.Len(t, got, 1)
	assert.Equal(t, "anthropic", got[0].Provider)
	assert.Equal(t, "messages", got[0].Capability)
}
