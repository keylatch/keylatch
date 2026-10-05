//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
// Uses a fake http.RoundTripper only — no real Connect server is contacted.
package opconnect

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

type stubRoundTripper func(*http.Request) (*http.Response, error)

func (f stubRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// KNOWN-FAILING: Set always issues a create request for a given
// canonical path instead of looking up an existing item first, so setting
// the same path twice creates a duplicate item rather than upserting.
func TestSecurityRegression_ConnectUpsert(t *testing.T) {
	creates := 0
	c := &http.Client{Transport: stubRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			creates++
		}
		return &http.Response{StatusCode: 201, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
	})}
	b, e := Open(Options{ConnectURL: "https://connect.invalid", Token: "synthetic", VaultID: "audit", HTTPClient: c})
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"first", "replacement"} {
		if e = b.Set(context.Background(), "default/ai/test/api_key", []byte(v), backend.Meta{}); e != nil {
			t.Fatal(e)
		}
	}
	if creates == 2 {
		t.Fatal("setting same canonical path twice issued two create requests without lookup or update")
	}
}
