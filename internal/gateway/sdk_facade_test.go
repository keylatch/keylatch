package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSDKFacade_UnsupportedPath verifies 404 for unsupported paths.
func TestSDKFacade_UnsupportedPath(t *testing.T) {
	s := &Server{
		opts:   ServerOptions{SigningKey: make([]byte, 32)},
		router: nil,
		broker: nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/unsupported/path", nil)
	rr := httptest.NewRecorder()
	s.gatewayHandler(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unsupported path; got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "sk-") || strings.Contains(body, "Bearer") {
		t.Error("404 response must be value-free")
	}
}

// TestSDKFacade_MissingAuthToken verifies 401 when no bearer token is supplied.
func TestSDKFacade_MissingAuthToken(t *testing.T) {
	s := &Server{
		opts:   ServerOptions{SigningKey: make([]byte, 32)},
		router: nil,
		broker: nil,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/openai/chat", nil)
	rr := httptest.NewRecorder()
	s.gatewayHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing token; got %d", rr.Code)
	}
}

// TestSDKFacade_ValueFreeErrorResponse verifies error responses contain no token values.
func TestSDKFacade_ValueFreeErrorResponse(t *testing.T) {
	s := &Server{
		opts:   ServerOptions{SigningKey: make([]byte, 32)},
		router: nil,
		broker: nil,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/openai/chat", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rr := httptest.NewRecorder()
	s.gatewayHandler(rr, req)

	body := rr.Body.String()
	// Error response must not echo back the supplied token.
	if strings.Contains(body, "invalid-token") {
		t.Errorf("error response echoed back token value: %s", body)
	}
}
