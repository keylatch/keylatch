package gateway

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/route"
	"github.com/keylatch/keylatch/internal/registry"
)

// Every route compiled from the embedded templates must reach its upstream
// through the SSRF gate; a template whose host is not allowed would fail every call.
func TestSSRFGate_AllowsEveryEmbeddedRoute(t *testing.T) {
	if err := registry.InitFromConfig(context.Background(), func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	router, err := route.Compile(registry.List())
	if err != nil {
		t.Fatal(err)
	}
	routes := router.Routes()
	if len(routes) == 0 {
		t.Fatal("no routes compiled")
	}
	g := NewSSRFGate()
	g.lookup = func(string) ([]string, error) { return []string{"93.184.216.34"}, nil }
	for _, rt := range routes {
		if rt.UpstreamHost == "" { // tenant-specific host the template cannot name
			continue
		}
		if _, err := g.Resolve(rt.Provider, rt.UpstreamHost); err != nil {
			t.Errorf("%s %s (%s): %v", rt.Method, rt.PathTemplate, rt.UpstreamHost, err)
		}
	}
}
