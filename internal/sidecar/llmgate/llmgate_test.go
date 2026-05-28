package llmgate_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	llmgate "github.com/keylatch/keylatch/internal/sidecar/llmgate"
)

func TestMiddlewarePassThroughWhenNotDesktopShell(t *testing.T) {
	// When fromDesktopShell=false, all requests pass through.
	mw := llmgate.Middleware(false)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rw.Code)
	}
}

func TestMiddlewarePassThroughWhenNotLLMSession(t *testing.T) {
	// When fromDesktopShell=true but no LLM signals, pass through.
	// LLM signals (CLAUDE_CODE, CODEX_ENV, etc.) are not set in tests.
	mw := llmgate.Middleware(true)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("expected 200 in non-LLM session, got %d", rw.Code)
	}
}

func TestMiddlewareBlocks403WhenLLMSession(t *testing.T) {
	// When fromDesktopShell=true AND CLAUDE_CODE is set, block with 403.
	t.Setenv("CLAUDE_CODE", "1")

	mw := llmgate.Middleware(true)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // should never reach here
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Errorf("expected 403 for LLM session, got %d", rw.Code)
	}
	body := rw.Body.String()
	if body == "" {
		t.Error("expected non-empty 403 body")
	}
	if !containsAny(body, "keylatch CLI", "CLI") {
		t.Errorf("expected 403 body to mention CLI, got %q", body)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
