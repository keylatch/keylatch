package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeTestHandler_ValidMode(t *testing.T) {
	initAPIRegistry(t)
	t.Parallel()
	h := &api.RuntimeTestHandler{Store: newAPIMemoryStore()}
	body := `{"runtime":"gateway_typed"}`
	req := httptest.NewRequest(http.MethodPost, "/api/connections/openrouter/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRuntimeTestHandler_InvalidMode(t *testing.T) {
	t.Parallel()
	h := &api.RuntimeTestHandler{}
	// direct_run is not a valid UI mode
	body := `{"runtime":"direct_run"}`
	req := httptest.NewRequest(http.MethodPost, "/api/connections/myconn/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestRuntimeTestHandler_UnrestrictedRejected(t *testing.T) {
	t.Parallel()
	h := &api.RuntimeTestHandler{}
	body := `{"runtime":"unrestricted"}`
	req := httptest.NewRequest(http.MethodPost, "/api/connections/myconn/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDoctorHandler_Success(t *testing.T) {
	t.Parallel()
	h := &api.DoctorHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/doctor/myconn", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestDoctorHandler_RouteRegistered asserts the route is registered, returns JSON,
// and includes the "exit" field with value 0 for a healthy system (W-06).
func TestDoctorHandler_RouteRegistered(t *testing.T) {
	t.Parallel()
	h := &api.DoctorHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/doctor?json=true", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Contains(t, body, "exit", "response must contain 'exit' field")
	assert.Contains(t, body, "healthy", "response must contain 'healthy' field")
	assert.Contains(t, body, "checks", "response must contain 'checks' field")
}

// TestDoctorHandler_ExitZeroWhenHealthy asserts exit=0 when OverallOK is true and
// there are no warnings (W-06).
func TestDoctorHandler_ExitZeroWhenHealthy(t *testing.T) {
	t.Parallel()
	h := &api.DoctorHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/doctor?json=true", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Exit    int  `json:"exit"`
		Healthy bool `json:"healthy"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	// In the test environment the doctor runs real checks.  We assert that if
	// healthy=true then exit must equal 0.  If healthy=false (environment issue)
	// we assert exit is non-zero but not fail the test on health itself.
	if body.Healthy {
		assert.Equal(t, 0, body.Exit, "healthy=true must produce exit=0")
	} else {
		assert.NotEqual(t, 0, body.Exit, "healthy=false must produce exit != 0")
	}
}

// TestDoctorHandler_ConnectionFilterParam asserts the ?connection= query param
// is accepted and does not cause an error response (W-06).
func TestDoctorHandler_ConnectionFilterParam(t *testing.T) {
	t.Parallel()
	h := &api.DoctorHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/doctor?connection=openrouter&json=true", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Contains(t, body, "exit")
}

// TestDoctorHandler_MethodNotAllowed asserts non-GET requests are rejected (W-06).
func TestDoctorHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := &api.DoctorHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/doctor", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
