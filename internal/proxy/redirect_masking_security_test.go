//go:build securitysuite

// Requires the "securitysuite" build tag; excluded from the ordinary
// `go test ./...` run because the proxy runtime isn't wired up for use yet.
// Run with: go test -tags securitysuite ./internal/proxy/...
package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

type stubTransport func(*http.Request) (*http.Response, error)

func (f stubTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type stubVault struct{}

func (stubVault) Get(context.Context, string) ([]byte, backend.Meta, error) {
	return []byte("synthetic-key"), backend.Meta{}, nil
}

func blockBodyProxyServer() *Server {
	return &Server{
		Token: "caller-token",
		Vault: stubVault{},
		Profile: ProxyProfile{
			Hosts: []string{"allowed.invalid"},
			Routes: []ProxyRoute{{
				Method:  "GET",
				Path:    "/api",
				Masking: MaskingLevelBlockBody,
				AuthInjection: AuthInjection{
					Placement: "header",
					Name:      "X-Api-Key",
					Value:     "{{ secret.default/ai/test/api_key }}",
				},
			}},
		},
	}
}

func doProxyRequest(s *Server) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://allowed.invalid/api", nil)
	r.Header.Set("Proxy-Authorization", "Bearer caller-token")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// KNOWN-FAILING (F27): httpClient() has no redirect policy, so a redirect
// destination never re-enters the host allowlist and the injected
// credential is forwarded to it.
func TestSecurityRegression_F27_ProxyRedirectDoesNotReenterHostAllowlist(t *testing.T) {
	s := blockBodyProxyServer()
	escaped := false
	s.httpClient().Transport = stubTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "allowed.invalid" {
			return &http.Response{
				StatusCode: 302,
				Header:     http.Header{"Location": []string{"https://outside.invalid/stolen"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    r,
			}, nil
		}
		escaped = r.Header.Get("X-Api-Key") == "synthetic-key"
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	doProxyRequest(s)
	if escaped {
		t.Fatal("redirect sent credential to host outside profile allowlist")
	}
}

// KNOWN-FAILING (F28): routeHandler streams the entire upstream body
// regardless of ProxyRoute.Masking, so a block_body route still returns the
// full response.
func TestSecurityRegression_F28_ProxyBlockBodyMaskingNotEnforced(t *testing.T) {
	s := blockBodyProxyServer()
	s.httpClient().Transport = stubTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("private-response")), Request: r}, nil
	})
	w := doProxyRequest(s)
	if strings.Contains(w.Body.String(), "private-response") {
		t.Fatal("block_body route returned complete upstream response")
	}
}
