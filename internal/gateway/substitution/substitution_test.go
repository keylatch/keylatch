package substitution_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/substitution"
)

func buildRequest(method, rawURL string, headers map[string]string) *http.Request {
	u, _ := url.Parse(rawURL)
	req := &http.Request{
		Method: method,
		URL:    u,
		Header: make(http.Header),
		Host:   u.Host,
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestCheckRequest_AuthHeader_Blocked(t *testing.T) {
	req := buildRequest("POST", "http://127.0.0.1:7878/api/openrouter/chat", map[string]string{
		"Authorization": "Bearer sk-or-hijack-attempt-token",
	})
	kind, err := substitution.CheckRequest(req, "openrouter.ai", nil, false)
	if err != substitution.ErrSubstitutionBlocked {
		t.Errorf("expected ErrSubstitutionBlocked, got %v", err)
	}
	if kind != "auth_header" {
		t.Errorf("expected kind=auth_header, got %q", kind)
	}
}

func TestCheckRequest_AuthHeader_AllowedWithAgentAuth(t *testing.T) {
	req := buildRequest("POST", "http://127.0.0.1:7878/api/openrouter/chat", map[string]string{
		"Authorization": "Bearer keylatch-internal",
	})
	kind, err := substitution.CheckRequest(req, "openrouter.ai", nil, true)
	if err != nil {
		t.Errorf("expected no error with allowAgentAuth=true, got %v (kind=%q)", err, kind)
	}
}

func TestCheckRequest_APIKeyParam_Blocked(t *testing.T) {
	req := buildRequest("POST", "http://127.0.0.1:7878/api/sentry/report?api_key=injected-key", nil)
	kind, err := substitution.CheckRequest(req, "sentry.io", nil, false)
	if err != substitution.ErrSubstitutionBlocked {
		t.Errorf("expected ErrSubstitutionBlocked, got %v", err)
	}
	if kind != "api_key_param" {
		t.Errorf("expected kind=api_key_param, got %q", kind)
	}
}

func TestCheckRequest_APIKeyParam_AllowedParam(t *testing.T) {
	req := buildRequest("POST", "http://127.0.0.1:7878/api/sentry/report?token=allowed", nil)
	allowed := map[string]bool{"token": true}
	_, err := substitution.CheckRequest(req, "sentry.io", allowed, false)
	if err != nil {
		t.Errorf("expected no error with allowed param, got %v", err)
	}
}

func TestCheckRequest_TokenEndpoint_Blocked(t *testing.T) {
	req := buildRequest("POST", "http://127.0.0.1:7878/oauth/token", nil)
	kind, err := substitution.CheckRequest(req, "api.example.com", nil, false)
	if err != substitution.ErrSubstitutionBlocked {
		t.Errorf("expected ErrSubstitutionBlocked, got %v", err)
	}
	if kind != "token_endpoint" {
		t.Errorf("expected kind=token_endpoint, got %q", kind)
	}
}

func TestCheckRequest_HostOverride_Blocked(t *testing.T) {
	req := buildRequest("POST", "http://127.0.0.1:7878/api/openrouter/chat", map[string]string{
		"X-Forwarded-Host": "evil.attacker.com",
	})
	kind, err := substitution.CheckRequest(req, "openrouter.ai", nil, false)
	if err != substitution.ErrSubstitutionBlocked {
		t.Errorf("expected ErrSubstitutionBlocked, got %v", err)
	}
	if kind != "host_override" {
		t.Errorf("expected kind=host_override, got %q", kind)
	}
}

func TestCheckRequest_CleanRequest_Passes(t *testing.T) {
	req := buildRequest("POST", "http://127.0.0.1:7878/api/openrouter/chat", map[string]string{
		"Content-Type": "application/json",
	})
	_, err := substitution.CheckRequest(req, "openrouter.ai", nil, false)
	if err != nil {
		t.Errorf("expected no error for clean request, got %v", err)
	}
}

func TestCheckRequest_NilRequest(t *testing.T) {
	_, err := substitution.CheckRequest(nil, "openrouter.ai", nil, false)
	if err != nil {
		t.Errorf("expected no error for nil request, got %v", err)
	}
}

func TestCheckRequest_OAuthEndpointVariant(t *testing.T) {
	paths := []string{
		"/login/oauth/access_token",
		"/oauth2/token",
	}
	for _, p := range paths {
		req := buildRequest("POST", "http://127.0.0.1:7878"+p, nil)
		kind, err := substitution.CheckRequest(req, "api.example.com", nil, false)
		if err != substitution.ErrSubstitutionBlocked {
			t.Errorf("path %q: expected ErrSubstitutionBlocked, got %v", p, err)
		}
		if kind != "token_endpoint" {
			t.Errorf("path %q: expected kind=token_endpoint, got %q", p, kind)
		}
	}
}
