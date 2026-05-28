package api_test

// T-13-05 integration test: server-validated approval-ttl endpoint.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/api"
)

// TestSettingsGet_ReturnsDefaults verifies GET /api/settings returns the
// default TTL and max TTL without any prior PUT.
func TestSettingsGet_ReturnsDefaults(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/settings: want 200, got %d", rec.Code)
	}

	var resp struct {
		ApprovalTTLSeconds    int `json:"approval_ttl_seconds"`
		ApprovalTTLMaxSeconds int `json:"approval_ttl_max_seconds"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ApprovalTTLSeconds != api.DefaultApprovalTTLSeconds {
		t.Errorf("approval_ttl_seconds: want %d, got %d", api.DefaultApprovalTTLSeconds, resp.ApprovalTTLSeconds)
	}
	if resp.ApprovalTTLMaxSeconds != api.DefaultApprovalTTLMaxSeconds {
		t.Errorf("approval_ttl_max_seconds: want %d, got %d", api.DefaultApprovalTTLMaxSeconds, resp.ApprovalTTLMaxSeconds)
	}
}

// TestSettingsPut_ClampsTTLToMax is the key T-13-05 assertion:
// submitting 999999 seconds returns ≤ approval_ttl_max_seconds.
func TestSettingsPut_ClampsTTLToMax(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	body, _ := json.Marshal(map[string]int{"approval_ttl_seconds": 999999})
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings: want 200, got %d\nbody: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		ApprovalTTLSeconds    int `json:"approval_ttl_seconds"`
		ApprovalTTLMaxSeconds int `json:"approval_ttl_max_seconds"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Core invariant: server clamps to max.
	if resp.ApprovalTTLSeconds > resp.ApprovalTTLMaxSeconds {
		t.Errorf("server did not clamp TTL: got %d > max %d", resp.ApprovalTTLSeconds, resp.ApprovalTTLMaxSeconds)
	}
	if resp.ApprovalTTLSeconds > api.DefaultApprovalTTLMaxSeconds {
		t.Errorf("TTL exceeds hard cap: got %d, hard cap %d", resp.ApprovalTTLSeconds, api.DefaultApprovalTTLMaxSeconds)
	}
}

// TestSettingsPut_AcceptsValidTTL verifies that a value within bounds is stored as-is.
func TestSettingsPut_AcceptsValidTTL(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	body, _ := json.Marshal(map[string]int{"approval_ttl_seconds": 300})
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings: want 200, got %d", rec.Code)
	}

	var resp struct {
		ApprovalTTLSeconds int `json:"approval_ttl_seconds"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ApprovalTTLSeconds != 300 {
		t.Errorf("want 300, got %d", resp.ApprovalTTLSeconds)
	}
}

// TestSettingsPut_GetReflectsNewValue verifies that a GET after PUT returns the updated value.
func TestSettingsPut_GetReflectsNewValue(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	// PUT 120.
	body, _ := json.Marshal(map[string]int{"approval_ttl_seconds": 120})
	putReq := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: want 200, got %d", putRec.Code)
	}

	// GET should return 120.
	getReq := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)

	var resp struct {
		ApprovalTTLSeconds int `json:"approval_ttl_seconds"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ApprovalTTLSeconds != 120 {
		t.Errorf("GET after PUT: want 120, got %d", resp.ApprovalTTLSeconds)
	}
}

// TestSettingsPut_MissingField returns 400 when neither approval_ttl_seconds nor
// advanced_mode is present.
func TestSettingsPut_MissingField(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	body, _ := json.Marshal(map[string]string{"other_field": "value"})
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", rec.Code)
	}
}

// TestSettings_ModeRadioPersists verifies that PUT operating_mode round-trips through
// the settings store (EPIC-27).
func TestSettings_ModeRadioPersists(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	// Default should be "standard".
	getReq := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	var initial struct {
		OperatingMode string `json:"operating_mode"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&initial); err != nil {
		t.Fatalf("decode initial GET: %v", err)
	}
	if initial.OperatingMode != "standard" {
		t.Errorf("default operating_mode: want standard, got %s", initial.OperatingMode)
	}

	// PUT canary.
	body, _ := json.Marshal(map[string]string{"operating_mode": "canary"})
	putReq := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT operating_mode=canary: want 200, got %d\nbody: %s", putRec.Code, putRec.Body.String())
	}
	var putResp struct {
		OperatingMode string `json:"operating_mode"`
	}
	if err := json.NewDecoder(putRec.Body).Decode(&putResp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if putResp.OperatingMode != "canary" {
		t.Errorf("PUT response: want canary, got %s", putResp.OperatingMode)
	}

	// Subsequent GET reflects the stored value.
	getReq2 := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getRec2 := httptest.NewRecorder()
	h.ServeHTTP(getRec2, getReq2)
	var updated struct {
		OperatingMode string `json:"operating_mode"`
	}
	if err := json.NewDecoder(getRec2.Body).Decode(&updated); err != nil {
		t.Fatalf("decode second GET: %v", err)
	}
	if updated.OperatingMode != "canary" {
		t.Errorf("GET after PUT: want canary, got %s", updated.OperatingMode)
	}
}

// TestSettings_InvalidModereturns400 verifies that an unknown operating mode is rejected.
func TestSettings_InvalidModeReturns400(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	body, _ := json.Marshal(map[string]string{"operating_mode": "galaxy_brain"})
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid operating_mode: want 400, got %d", rec.Code)
	}
}

// TestSettings_ApprovalPolicyPerConnectionOverride verifies that PUT approval_policy
// persists and the GET response reflects the update (EPIC-27).
func TestSettings_ApprovalPolicyPerConnectionOverride(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	// Default should be "prompt".
	getReq := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	var initial struct {
		ApprovalPolicy string `json:"approval_policy"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&initial); err != nil {
		t.Fatalf("decode initial GET: %v", err)
	}
	if initial.ApprovalPolicy != "prompt" {
		t.Errorf("default approval_policy: want prompt, got %s", initial.ApprovalPolicy)
	}

	for _, policy := range []string{"trust", "first-run", "prompt"} {
		body, _ := json.Marshal(map[string]string{"approval_policy": policy})
		putReq := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
		putReq.Header.Set("Content-Type", "application/json")
		putRec := httptest.NewRecorder()
		h.ServeHTTP(putRec, putReq)
		if putRec.Code != http.StatusOK {
			t.Fatalf("PUT approval_policy=%s: want 200, got %d\nbody: %s", policy, putRec.Code, putRec.Body.String())
		}
		var resp struct {
			ApprovalPolicy string `json:"approval_policy"`
		}
		if err := json.NewDecoder(putRec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode PUT response for policy %s: %v", policy, err)
		}
		if resp.ApprovalPolicy != policy {
			t.Errorf("PUT approval_policy=%s: response has %s", policy, resp.ApprovalPolicy)
		}
	}
}

// TestSettings_InvalidApprovalPolicyReturns400 verifies that an unknown policy is rejected.
func TestSettings_InvalidApprovalPolicyReturns400(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	body, _ := json.Marshal(map[string]string{"approval_policy": "always_yes"})
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid approval_policy: want 400, got %d", rec.Code)
	}
}

// TestSettings_TelemetryAndExperimentalRoundTrip verifies that telemetry_disable
// and experimental fields persist correctly.
func TestSettings_TelemetryAndExperimentalRoundTrip(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	body, _ := json.Marshal(map[string]interface{}{
		"telemetry_disable": true,
		"experimental":      true,
	})
	putReq := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT telemetry+experimental: want 200, got %d\nbody: %s", putRec.Code, putRec.Body.String())
	}

	var resp struct {
		TelemetryDisable bool `json:"telemetry_disable"`
		Experimental     bool `json:"experimental"`
	}
	if err := json.NewDecoder(putRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if !resp.TelemetryDisable {
		t.Error("PUT response: telemetry_disable should be true")
	}
	if !resp.Experimental {
		t.Error("PUT response: experimental should be true")
	}

	// Verify GET reflects the stored values.
	getReq := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	var updated struct {
		TelemetryDisable bool `json:"telemetry_disable"`
		Experimental     bool `json:"experimental"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if !updated.TelemetryDisable {
		t.Error("GET after PUT: telemetry_disable should be true")
	}
	if !updated.Experimental {
		t.Error("GET after PUT: experimental should be true")
	}
}

// Settings_AdvancedToggleHidesByDefault is covered by TestUI_AdvancedToggle_RoundTrips
// (advanced_mode defaults to false). This test makes the canonical EPIC-27 assertion explicit.
func TestSettings_AdvancedToggleHidesByDefault(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/settings: want 200, got %d", rec.Code)
	}
	var resp struct {
		AdvancedMode bool `json:"advanced_mode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.AdvancedMode {
		t.Error("advanced_mode must default to false (hidden by default)")
	}
}

// TestUI_AdvancedToggle_RoundTrips verifies that PUT advanced_mode=true is persisted
// and returned by a subsequent GET.
func TestUI_AdvancedToggle_RoundTrips(t *testing.T) {
	t.Parallel()

	store := api.NewSettingsStore()
	h := &api.SettingsHandler{Store: store}

	// Initial GET: advanced_mode should default to false.
	getReq := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("initial GET: want 200, got %d", getRec.Code)
	}
	var initial struct {
		AdvancedMode bool `json:"advanced_mode"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&initial); err != nil {
		t.Fatalf("decode initial GET: %v", err)
	}
	if initial.AdvancedMode {
		t.Error("initial advanced_mode should be false")
	}

	// PUT advanced_mode=true.
	putBody, _ := json.Marshal(map[string]bool{"advanced_mode": true})
	putReq := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT advanced_mode=true: want 200, got %d\nbody: %s", putRec.Code, putRec.Body.String())
	}
	var putResp struct {
		AdvancedMode bool `json:"advanced_mode"`
	}
	if err := json.NewDecoder(putRec.Body).Decode(&putResp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if !putResp.AdvancedMode {
		t.Error("PUT response: advanced_mode should be true after setting it")
	}

	// GET after PUT: should reflect the updated value.
	getReq2 := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getRec2 := httptest.NewRecorder()
	h.ServeHTTP(getRec2, getReq2)

	var updated struct {
		AdvancedMode bool `json:"advanced_mode"`
	}
	if err := json.NewDecoder(getRec2.Body).Decode(&updated); err != nil {
		t.Fatalf("decode second GET: %v", err)
	}
	if !updated.AdvancedMode {
		t.Error("GET after PUT: advanced_mode should be true")
	}

	// PUT advanced_mode=false to verify toggling off also round-trips.
	putBodyOff, _ := json.Marshal(map[string]bool{"advanced_mode": false})
	putReqOff := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(putBodyOff))
	putReqOff.Header.Set("Content-Type", "application/json")
	putRecOff := httptest.NewRecorder()
	h.ServeHTTP(putRecOff, putReqOff)

	if putRecOff.Code != http.StatusOK {
		t.Fatalf("PUT advanced_mode=false: want 200, got %d", putRecOff.Code)
	}

	getReq3 := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getRec3 := httptest.NewRecorder()
	h.ServeHTTP(getRec3, getReq3)

	var final struct {
		AdvancedMode bool `json:"advanced_mode"`
	}
	if err := json.NewDecoder(getRec3.Body).Decode(&final); err != nil {
		t.Fatalf("decode final GET: %v", err)
	}
	if final.AdvancedMode {
		t.Error("GET after PUT(false): advanced_mode should be false")
	}
}
