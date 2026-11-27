package route_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/route"
	"github.com/keylatch/keylatch/internal/registry"
)

// A compiled route carries its template's deny_routes and forward_headers, so
// the handler can refuse a credential route and forward declared headers.
func TestCompileCarriesDenyRoutesAndForwardHeaders(t *testing.T) {
	tmpl := registry.ConnectionTemplate{
		Provider: "svc",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
		GatewayActions: []registry.GatewayAction{{Name: "list", Method: "GET", UpstreamPath: "/v1/api_keys"}},
		TestStrategy:   registry.TestStrategy{Endpoint: "https://api.svc.example/v1/ping"},
		DenyRoutes:     []string{"/v1/api_keys"},
		ForwardHeaders: []string{"X-Svc-Version"},
	}
	r, err := route.Compile([]registry.ConnectionTemplate{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	rt, ok := r.Match("GET", "/api/svc/list")
	if !ok {
		t.Fatal("route not compiled")
	}
	if !registry.RouteDenied(rt.DenyRoutes, rt.Method, rt.UpstreamPath) {
		t.Errorf("route %s %s is not denied: %v", rt.Method, rt.UpstreamPath, rt.DenyRoutes)
	}
	if len(rt.ForwardHeaders) != 1 || rt.ForwardHeaders[0] != "X-Svc-Version" {
		t.Errorf("forward headers = %v", rt.ForwardHeaders)
	}
}
