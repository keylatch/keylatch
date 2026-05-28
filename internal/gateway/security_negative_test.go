package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

// okHandler is a trivial handler that returns 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
})

// TestSecurity_AuthorizationHeaderPassesThroughMiddleware verifies that the
// Authorization header is NOT blocked at the authBlocker layer — the gateway
// consumes it as the keylatch session JWT in token.Verify, and the handler
// strips it before forwarding upstream. Blocking it at the middleware would
// prevent agents from authenticating to the gateway at all. Upstream
// credential isolation is enforced by the handler's strip-and-inject logic.
func TestSecurity_AuthorizationHeaderPassesThroughMiddleware(t *testing.T) {
	handler := authBlockerMiddleware(okHandler, false)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer sk-canary-PHASE13-should-not-pass")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Middleware must pass through; the underlying handler (or token.Verify
	// downstream) is responsible for rejecting invalid JWTs.
	if rr.Code != http.StatusOK {
		t.Errorf("expected middleware to pass Authorization through; got %d", rr.Code)
	}
}

// TestSecurity_ApiKeyQueryParamBlocked verifies api_key query param is blocked.
func TestSecurity_ApiKeyQueryParamBlocked(t *testing.T) {
	handler := authBlockerMiddleware(okHandler, false)

	req := httptest.NewRequest(http.MethodGet, "/api/test?api_key=sk-secret", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for api_key query param; got %d", rr.Code)
	}
}

// TestSecurity_BearerTokenInBodyBlocked verifies Bearer token in body is blocked.
func TestSecurity_BearerTokenInBodyBlocked(t *testing.T) {
	handler := authBlockerMiddleware(okHandler, false)

	body := `{"message":"Bearer sk-canary-PHASE13-0xDEADBEEF"}`
	req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for Bearer token in body; got %d", rr.Code)
	}
}

// TestSecurity_TokenEndpointDirectCallBlocked verifies /oauth/token calls are blocked.
func TestSecurity_TokenEndpointDirectCallBlocked(t *testing.T) {
	handler := authBlockerMiddleware(okHandler, false)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for /oauth/token direct call; got %d", rr.Code)
	}
}

// TestSecurity_SSRFToIMDSBlocked verifies the SSRF gate blocks 169.254.169.254.
func TestSecurity_SSRFToIMDSBlocked(t *testing.T) {
	gate := NewSSRFGate()
	err := gate.Validate("openai", "169.254.169.254")
	if err == nil {
		t.Error("expected SSRF error for IMDS IP; got nil")
	}
}

// TestSecurity_SSRFToRFC1918Blocked verifies the SSRF gate blocks 10.0.0.1.
func TestSecurity_SSRFToRFC1918Blocked(t *testing.T) {
	gate := NewSSRFGate()
	err := gate.Validate("openai", "10.0.0.1")
	if err == nil {
		t.Error("expected SSRF error for RFC 1918 IP; got nil")
	}
}

// TestSecurity_XForwardedHostBlocked verifies X-Forwarded-Host is blocked.
func TestSecurity_XForwardedHostBlocked(t *testing.T) {
	handler := hostOverrideBlockerMiddleware(okHandler, []string{"api.openai.com"})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("X-Forwarded-Host", "evil.attacker.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for X-Forwarded-Host override; got %d", rr.Code)
	}
}

// TestSecurity_LegitimateRequestPassesThrough verifies a clean request is not blocked.
func TestSecurity_LegitimateRequestPassesThrough(t *testing.T) {
	// No Authorization header, no suspicious params, no token endpoint.
	handler := authBlockerMiddleware(okHandler, false)

	req := httptest.NewRequest(http.MethodPost, "/api/openai/chat", strings.NewReader(`{"model":"gpt-4"}`))
	req.ContentLength = int64(len(`{"model":"gpt-4"}`))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for legitimate request; got %d", rr.Code)
	}
}

// TestSecurity_TemplateWithIMDSURLRejected verifies ValidateTemplateBaseURL rejects IMDS.
func TestSecurity_TemplateWithIMDSURLRejected(t *testing.T) {
	err := registry.ValidateTemplateBaseURL("openai", "http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Error("expected error for IMDS URL in template; got nil")
	}
}
