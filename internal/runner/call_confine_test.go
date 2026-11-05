package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/template"
)

func registerConfineProvider(t *testing.T) {
	t.Helper()
	err := registry.Register(registry.ConnectionTemplate{
		Provider: "confine-demo", DisplayName: "Confine demo", Category: "test", AuthFlow: "api_key",
		AuthPlacement:  registry.AuthPlacement{In: "header", Name: "Authorization", Scheme: "Bearer"},
		StoragePathTpl: "default/test/confine-demo/default",
		TrustLevel:     registry.TrustLocalOnly,
		RuntimeSupport: registry.RuntimeSupport{Preferred: registry.RuntimeGatewayTyped, Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped}},
		SecretFields:   []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
		TestStrategy:   registry.TestStrategy{Kind: "http_get", Endpoint: "https://example.com/health", Expect: registry.TestExpectation{StatusCode: 200}},
		DenyRoutes:     []string{"GET /v1/keys/**"},
		Actions: map[string]template.Action{
			"get-item": {Method: "GET", Path: "/v1/items/{id}", Params: map[string]template.ParamSpec{"id": {In: "path", Required: true}}},
		},
	})
	if err != nil && !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
}

func TestPathParamCannotWalkOutOfTheAction(t *testing.T) {
	registerConfineProvider(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	for _, id := range []string{"..", ".", "../keys/x", "a/b", `a\b`, "", "a\x00b", "a\nb"} {
		if _, err := ExecuteAction(context.Background(), srv.URL, "confine-demo", "get-item", map[string]string{"id": id}, "tok"); err == nil {
			t.Errorf("id %q was accepted", id)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached the server", hits.Load())
	}
	if _, err := ExecuteAction(context.Background(), srv.URL, "confine-demo", "get-item", map[string]string{"id": "abc-1"}, "tok"); err != nil || hits.Load() != 1 {
		t.Fatalf("a plain id: %v (%d hits)", err, hits.Load())
	}
}

func TestConfineActionURL(t *testing.T) {
	registerConfineProvider(t)
	tmpl, err := registry.Get("confine-demo")
	if err != nil {
		t.Fatal(err)
	}
	act := tmpl.Actions["get-item"]
	const base = "https://api.confine.test"
	ok := func(raw string) {
		t.Helper()
		if got, err := confineActionURL(raw, base, tmpl, act); err != nil || got != raw {
			t.Errorf("%s = %q, %v", raw, got, err)
		}
	}
	bad := func(raw, baseURL string) {
		t.Helper()
		if got, err := confineActionURL(raw, baseURL, tmpl, act); err == nil {
			t.Errorf("%s against %s was allowed: %s", raw, baseURL, got)
		}
	}
	ok("https://api.confine.test/v1/items/abc?x=1")
	ok("https://api.confine.test/v1/items/")
	bad("https://evil.test/v1/items/abc", base)
	bad("http://api.confine.test/v1/items/abc", base)
	bad("https://user@api.confine.test/v1/items/abc", base)
	bad("https://api.confine.test/v1/items/../keys/abc", base)
	bad("https://api.confine.test/v1/keys/abc", base)
	bad("https://api.confine.test/v1/items/abc", "ftp://api.confine.test")
	bad("https://api.confine.test/v1/items/abc", "")
	bad("https://api.confine.test/other", "https://api.confine.test/v1")
	if _, err := confineActionURL("https://api.confine.test/v1/items/abc", "https://api.confine.test/v1", tmpl, act); err != nil {
		t.Errorf("a base path was refused: %v", err)
	}
}
