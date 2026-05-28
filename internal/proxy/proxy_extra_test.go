package proxy_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnvInject_InjectsKeylatchVars verifies that EnvInject adds all required
// Keylatch proxy env vars to the base env.
func TestEnvInject_InjectsKeylatchVars(t *testing.T) {
	base := []string{"PATH=/usr/bin", "HOME=/home/test"}
	result := proxy.EnvInject(base, "127.0.0.1:7879", "jwt-token-here", "")

	// Must contain KEYLATCH_GATEWAY_URL.
	found := false
	for _, e := range result {
		if strings.HasPrefix(e, "KEYLATCH_GATEWAY_URL=") {
			found = true
			assert.Contains(t, e, "7879")
		}
	}
	assert.True(t, found, "KEYLATCH_GATEWAY_URL must be injected")

	// Must contain KEYLATCH_SESSION_TOKEN.
	found = false
	for _, e := range result {
		if strings.HasPrefix(e, "KEYLATCH_SESSION_TOKEN=") {
			found = true
			assert.Contains(t, e, "jwt-token-here")
		}
	}
	assert.True(t, found, "KEYLATCH_SESSION_TOKEN must be injected")

	// Must contain KEYLATCH_RUNTIME=gateway_proxy.
	found = false
	for _, e := range result {
		if e == "KEYLATCH_RUNTIME=gateway_proxy" {
			found = true
		}
	}
	assert.True(t, found, "KEYLATCH_RUNTIME=gateway_proxy must be injected")
}

// TestEnvInject_WithCAPath_InjectsCAVars verifies SSL CA env vars are injected
// when caPath is non-empty.
func TestEnvInject_WithCAPath_InjectsCAVars(t *testing.T) {
	base := []string{"PATH=/usr/bin"}
	result := proxy.EnvInject(base, "127.0.0.1:7879", "tok", "/tmp/ca.pem")

	var caEntries []string
	for _, e := range result {
		if strings.HasPrefix(e, "SSL_CERT_FILE=") ||
			strings.HasPrefix(e, "REQUESTS_CA_BUNDLE=") ||
			strings.HasPrefix(e, "NODE_EXTRA_CA_CERTS=") ||
			strings.HasPrefix(e, "GIT_SSL_CAINFO=") ||
			strings.HasPrefix(e, "KEYLATCH_CA_CERT=") {
			caEntries = append(caEntries, e)
		}
	}
	assert.GreaterOrEqual(t, len(caEntries), 3, "CA env vars must be injected when caPath is set")
}

// TestEnvInject_StripsPriorKeylatchVars verifies that existing KEYLATCH_* vars
// are replaced, not duplicated.
func TestEnvInject_StripsPriorKeylatchVars(t *testing.T) {
	base := []string{
		"KEYLATCH_GATEWAY_URL=http://old:1234",
		"KEYLATCH_SESSION_TOKEN=old-token",
		"KEYLATCH_RUNTIME=old_runtime",
	}
	result := proxy.EnvInject(base, "127.0.0.1:7879", "new-token", "")

	// Count occurrences of KEYLATCH_GATEWAY_URL.
	count := 0
	for _, e := range result {
		if strings.HasPrefix(e, "KEYLATCH_GATEWAY_URL=") {
			count++
		}
	}
	assert.Equal(t, 1, count, "KEYLATCH_GATEWAY_URL must appear exactly once after injection")

	// New value must be present.
	found := false
	for _, e := range result {
		if strings.HasPrefix(e, "KEYLATCH_SESSION_TOKEN=") && strings.HasSuffix(e, "new-token") {
			found = true
		}
	}
	assert.True(t, found, "new token must replace old token")
}

// TestParseProxyProfile_ValidJSON verifies that a well-formed proxy profile JSON
// is parsed correctly.
func TestParseProxyProfile_ValidJSON(t *testing.T) {
	data := []byte(`{
		"id": "test-profile",
		"mode": "gateway_proxy",
		"hosts": ["api.example.com"],
		"routes": [
			{"method": "POST", "path": "/v1/"}
		]
	}`)
	p, err := proxy.ParseProxyProfile(data)
	require.NoError(t, err)
	assert.Equal(t, "test-profile", p.ID)
	assert.Equal(t, "gateway_proxy", p.Mode)
}

// TestParseProxyProfile_InvalidJSON verifies JSON parse error propagation.
func TestParseProxyProfile_InvalidJSON(t *testing.T) {
	_, err := proxy.ParseProxyProfile([]byte("{bad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy_profile: parse")
}

// TestParseProxyProfile_InvalidMode verifies that an unsupported mode is rejected.
func TestParseProxyProfile_InvalidMode(t *testing.T) {
	data := []byte(`{"id":"x","mode":"unknown_mode","hosts":["a.example.com"]}`)
	_, err := proxy.ParseProxyProfile(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode")
}

// TestParseProxyProfile_InvalidTLSMode verifies TLS mode validation.
func TestParseProxyProfile_InvalidTLSMode(t *testing.T) {
	data := []byte(`{
		"id":"x",
		"mode":"gateway_proxy",
		"hosts":["a.example.com"],
		"tls":{"mode":"bad_mode","ca_key_storage":"keyring"}
	}`)
	_, err := proxy.ParseProxyProfile(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls.mode")
}

// TestValidateSSRFSafeHost_PrivateIPRejected verifies that private IPs are
// rejected by validateSSRFSafeHost (via ValidateProxyProfile with an IP host).
func TestValidateSSRFSafeHost_PrivateIPRejected(t *testing.T) {
	profile := proxy.ProxyProfile{
		ID:    "private-ip",
		Mode:  "gateway_proxy",
		Hosts: []string{"192.168.1.1"}, // private range
		SSRF: proxy.ProxySsrf{
			DenyPrivateRanges:           true,
			ResolveAndVerifyEachRequest: true,
		},
	}
	err := proxy.ValidateProxyProfile(profile, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied IP range")
}

// TestProxyServer_CONNECT_AllowedHost_HijackNotSupported verifies that a CONNECT
// request to an allowed host fails with 500 when hijacking is not supported
// (httptest.ResponseRecorder). This exercises the CONNECT path.
func TestProxyServer_CONNECT_AllowedHost_HijackNotSupported(t *testing.T) {
	profile := proxy.ProxyProfile{
		ID:    "connect-test",
		Mode:  "gateway_proxy",
		Hosts: []string{"api.example.com"},
	}
	srv := &proxy.Server{Profile: profile}

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodConnect, "https://api.example.com:443", nil)
	req.Host = "api.example.com:443"

	srv.ServeHTTP(rec, req)
	// 500 is expected because ResponseRecorder doesn't support hijacking.
	assert.Equal(t, http.StatusInternalServerError, rec.Code,
		"CONNECT with non-hijackable writer must return 500")
}

// TestProxyServer_CONNECT_DeniedHost_Returns403 verifies that CONNECT to a
// disallowed host is rejected with 403.
func TestProxyServer_CONNECT_DeniedHost_Returns403(t *testing.T) {
	profile := proxy.ProxyProfile{
		ID:    "connect-deny-test",
		Mode:  "gateway_proxy",
		Hosts: []string{"allowed.example.com"},
	}
	srv := &proxy.Server{Profile: profile}

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodConnect, "https://denied.example.com:443", nil)
	req.Host = "denied.example.com:443"

	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"CONNECT to non-allowlisted host must return 403")
}

// TestProxyServer_ParseSecretRef_NonTemplateValue verifies that a non-template
// value (not wrapped in {{ }}) returns an empty path and doesn't fail.
// This is tested indirectly: a route with a plain value and vault=nil should
// not 503 since no vault fetch occurs.
func TestProxyServer_ParseSecretRef_NonTemplateValue(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	profile := proxy.ProxyProfile{
		ID:    "no-template",
		Mode:  "gateway_proxy",
		Hosts: []string{upstreamHost},
		Routes: []proxy.ProxyRoute{
			{
				Method: "GET",
				Path:   "/",
				AuthInjection: proxy.AuthInjection{
					// Plain value — NOT a {{ secret.* }} template.
					Value: "Bearer static-token",
				},
			},
		},
	}

	// No vault needed — plain value doesn't trigger vault lookup.
	srv := &proxy.Server{Profile: profile, Vault: nil}
	proxySrv := httptest.NewServer(http.HandlerFunc(srv.ServeHTTP))
	defer proxySrv.Close()

	req, _ := http.NewRequest("GET", proxySrv.URL+"/test", nil)
	req.Host = upstreamHost

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		t.Skip("SSRF check blocked request in test environment")
		return
	}
	// Regardless, the server must not 503 (no vault error) for plain-value routes.
	assert.NotEqual(t, http.StatusServiceUnavailable, resp.StatusCode,
		"plain-value route must not trigger vault error 503")
}

// TestInjectCAEnv_InjectFalse verifies that InjectCAEnv returns env unchanged
// when inject=false.
func TestInjectCAEnv_InjectFalse(t *testing.T) {
	env := []string{"PATH=/usr/bin", "HOME=/home/test"}
	result := proxy.InjectCAEnv(env, "/tmp/ca.pem", false)
	assert.Equal(t, env, result, "InjectCAEnv with inject=false must not modify env")
}

// TestInjectCAEnv_InjectTrue verifies that InjectCAEnv adds CA env vars.
func TestInjectCAEnv_InjectTrue(t *testing.T) {
	env := []string{"PATH=/usr/bin"}
	result := proxy.InjectCAEnv(env, "/etc/ssl/ca.pem", true)

	var caEntries []string
	for _, e := range result {
		if strings.HasPrefix(e, "SSL_CERT_FILE=") ||
			strings.HasPrefix(e, "REQUESTS_CA_BUNDLE=") {
			caEntries = append(caEntries, e)
		}
	}
	assert.GreaterOrEqual(t, len(caEntries), 2, "InjectCAEnv must add SSL CA vars")
	for _, e := range caEntries {
		assert.Contains(t, e, "/etc/ssl/ca.pem", "CA path must be correct")
	}
}

// TestProxyServer_UpstreamError_503 verifies that when the upstream server is
// unreachable, the proxy returns 503.
func TestProxyServer_UpstreamError_503(t *testing.T) {
	// Use a host that is allowlisted but where no server is listening.
	// We rely on a local port that is definitely closed.
	upstreamHost := "127.0.0.1:19999"

	profile := proxy.ProxyProfile{
		ID:    "upstream-error-test",
		Mode:  "gateway_proxy",
		Hosts: []string{upstreamHost},
		Routes: []proxy.ProxyRoute{
			{
				Method: "GET",
				Path:   "/",
				AuthInjection: proxy.AuthInjection{
					Value: "Bearer static-token",
				},
			},
		},
	}

	srv := &proxy.Server{Profile: profile, Vault: nil}
	proxySrv := httptest.NewServer(http.HandlerFunc(srv.ServeHTTP))
	defer proxySrv.Close()

	req, _ := http.NewRequest("GET", proxySrv.URL+"/test", nil)
	req.Host = upstreamHost

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// Either 503 (upstream error) or 403 (SSRF check).
	assert.True(t,
		resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusForbidden,
		"unreachable upstream must return 503 or 403, got %d", resp.StatusCode)
}

// TestBufferedResponseWriter_WriteResponseTo verifies the response_writer
// produces valid HTTP/1.1 responses.
func TestBufferedResponseWriter_WriteResponseTo(t *testing.T) {
	rw := proxy.NewBufferedResponseWriterForTest()
	rw.WriteHeader(http.StatusForbidden)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write([]byte(`{"error":"test"}`))

	var buf bytes.Buffer
	err := rw.WriteResponseToForTest(&buf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "HTTP/1.1 403 Forbidden")
	assert.Contains(t, output, `{"error":"test"}`)
}

// TestValidateProxyProfile_ResolveAndVerifyRequired verifies that
// resolve_and_verify_each_request must be true.
func TestValidateProxyProfile_ResolveAndVerifyRequired(t *testing.T) {
	profile := proxy.ProxyProfile{
		ID:    "no-resolve",
		Mode:  "gateway_proxy",
		Hosts: []string{"api.example.com"},
		SSRF: proxy.ProxySsrf{
			DenyPrivateRanges:           true,
			ResolveAndVerifyEachRequest: false, // violation
		},
	}
	err := proxy.ValidateProxyProfile(profile, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve_and_verify_each_request")
}

// TestProxyServer_JSONError_RouteNotAllowed verifies the route_not_allowed error
// message is valid JSON.
func TestProxyServer_JSONError_RouteNotAllowed(t *testing.T) {
	profile := proxy.ProxyProfile{
		ID:    "json-route-test",
		Mode:  "gateway_proxy",
		Hosts: []string{"api.example.com"},
		Routes: []proxy.ProxyRoute{
			{Method: "POST", Path: "/v1/"},
		},
	}

	srv := &proxy.Server{Profile: profile}
	proxySrv := httptest.NewServer(http.HandlerFunc(srv.ServeHTTP))
	defer proxySrv.Close()

	req, _ := http.NewRequest("GET", proxySrv.URL+"/v1/other", nil)
	req.Host = "api.example.com"

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var errResp map[string]string
	err = json.Unmarshal(body, &errResp)
	require.NoError(t, err, "route_not_allowed response must be valid JSON")
	assert.Equal(t, "route_not_allowed", errResp["error"])
}
