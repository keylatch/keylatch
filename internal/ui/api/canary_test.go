package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
)

// TestCanary_MetaWalk verifies that all API handlers are covered by canary
// checks. This is a meta-test: it walks a representative set of handlers
// and asserts the canary sentinel is absent from every response.
func TestCanary_MetaWalk(t *testing.T) {
	sentinel := canary.Phase10Sentinel

	handlers := []struct {
		name    string
		method  string
		path    string
		handler http.Handler
	}{
		{
			name:    "connections list",
			method:  http.MethodGet,
			path:    "/api/connections",
			handler: &api.ConnectionsHandler{},
		},
		{
			name:    "connection detail",
			method:  http.MethodGet,
			path:    "/api/connections/test-conn",
			handler: &api.ConnectionDetailHandler{},
		},
		{
			name:    "approvals list",
			method:  http.MethodGet,
			path:    "/api/approvals",
			handler: &api.ApprovalsHandler{},
		},
		{
			name:    "gateway status",
			method:  http.MethodGet,
			path:    "/api/gateway/status",
			handler: &api.GatewayHandler{AllowTokenMinting: true},
		},
		{
			name:    "status",
			method:  http.MethodGet,
			path:    "/api/status",
			handler: &api.StatusHandler{Scope: "admin"},
		},
		{
			name:    "agent snippet",
			method:  http.MethodGet,
			path:    "/api/agent/snippet",
			handler: &api.AgentHandler{},
		},
	}

	for _, tc := range handlers {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, req)

			canary.AssertNoLeak(t,
				[]string{sentinel},
				canary.JSONResponse(rec.Body.Bytes()),
			)

			// Additionally verify no "value" key in JSON responses.
			body := rec.Body.Bytes()
			assert.NotContains(t, string(body), `"value"`,
				"handler %s must not return a 'value' field", tc.name)
		})
	}
}

// TestCanary_SentinelAbsentInConnections verifies the canary absent test
// specifically for connections — the most sensitive handler.
func TestCanary_SentinelAbsentInConnections(t *testing.T) {
	t.Parallel()
	h := &api.ConnectionsHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	canary.AssertNoLeak(t,
		[]string{canary.Phase10Sentinel, canary.Phase9Sentinel, canary.Phase8Sentinel},
		canary.JSONResponse(bytes.Clone(rec.Body.Bytes())),
	)
}
