package gateway

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type stubRoundTripper func(*http.Request) (*http.Response, error)

func (f stubRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// KNOWN-FAILING (F31): newProviderHTTPClient has no CheckRedirect, so a
// cross-host HTTPS-to-HTTP redirect forwards custom auth headers to the
// redirect target.
func TestSecurityRegression_F31_GatewayRedirect(t *testing.T) {
	c := newProviderHTTPClient()
	escaped := false
	c.Transport = stubRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "allowed.invalid" {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"http://outside.invalid/leak"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}
		escaped = r.Header.Get("X-Api-Key") == "synthetic-audit-key"
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	r, _ := http.NewRequest("GET", "https://allowed.invalid/", nil)
	r.Header.Set("X-Api-Key", "synthetic-audit-key")
	resp, e := c.Do(r)
	if e == nil {
		resp.Body.Close()
	}
	if escaped {
		t.Fatal("production gateway HTTP client forwarded custom credential on cross-host HTTPS-to-HTTP redirect")
	}
}
