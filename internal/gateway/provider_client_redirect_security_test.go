//go:build securitysuite

package gateway

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type stubRoundTripper func(*http.Request) (*http.Response, error)

func (f stubRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSecurityRegression_GatewayRedirect(t *testing.T) {
	tests := []struct {
		name       string
		location   string
		wantFollow bool
	}{
		{name: "cross-host https to https", location: "https://outside.invalid/leak"},
		{name: "cross-host https to http", location: "http://outside.invalid/leak"},
		{name: "same-host https to http downgrade", location: "http://allowed.invalid/leak"},
		{name: "same-host https to https", location: "https://allowed.invalid/next", wantFollow: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newProviderHTTPClient()
			followed := false
			c.Transport = stubRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/" {
					return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{tc.location}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
				}
				followed = r.Header.Get("X-Api-Key") == "synthetic-audit-key"
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			r, _ := http.NewRequest("GET", "https://allowed.invalid/", nil)
			r.Header.Set("X-Api-Key", "synthetic-audit-key")
			resp, err := c.Do(r)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			resp.Body.Close()
			if followed != tc.wantFollow {
				t.Fatalf("redirect followed with credential = %v, want %v", followed, tc.wantFollow)
			}
		})
	}
}
