package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
)

// TestGatewayHandler_Status verifies that GET /api/gateway/status returns 501
// Not Implemented (Q-1: gateway status not yet wired to real gateway).
func TestGatewayHandler_Status(t *testing.T) {
	t.Parallel()
	h := &api.GatewayHandler{AllowTokenMinting: false}
	req := httptest.NewRequest(http.MethodGet, "/api/gateway/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestGatewayHandler_TokenMinting_AdminScopeForbidden(t *testing.T) {
	t.Parallel()
	h := &api.GatewayHandler{AllowTokenMinting: false}
	req := httptest.NewRequest(http.MethodPost, "/api/gateway/tokens", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestGatewayHandler_TokenMinting_TokenScopeOK verifies that POST /api/gateway/tokens
// returns 501 Not Implemented (Q-1: token minting not yet wired to real gateway).
func TestGatewayHandler_TokenMinting_TokenScopeOK(t *testing.T) {
	t.Parallel()
	h := &api.GatewayHandler{AllowTokenMinting: true}
	req := httptest.NewRequest(http.MethodPost, "/api/gateway/tokens", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestBrokerHandler_DryRun_501(t *testing.T) {
	t.Parallel()
	h := &api.BrokerHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/broker/dry-run", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}
