package route_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/route"
	"github.com/keylatch/keylatch/internal/registry"
)

func testTemplates() []registry.ConnectionTemplate {
	return []registry.ConnectionTemplate{
		{
			Provider: "openrouter",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeGatewaySDK,
				Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK, registry.RuntimeGatewayTyped},
			},
			AuthPlacement: registry.AuthPlacement{In: "header", Name: "Authorization", Scheme: "Bearer"},
			Capabilities: []registry.Capability{
				{Name: "chat_completion"},
				{Name: "model_listing"},
			},
			Redaction: []registry.RedactionRule{
				{Pattern: `sk-or-[A-Za-z0-9\-_]{20,}`, Replacement: "****"},
			},
			TestStrategy: registry.TestStrategy{
				Endpoint: "https://openrouter.ai/api/v1/models",
			},
		},
		{
			Provider: "sentry",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeGatewayTyped,
				Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
			},
			AuthPlacement: registry.AuthPlacement{In: "header", Name: "Authorization", Scheme: "Bearer"},
			Capabilities: []registry.Capability{
				{Name: "error_reporting"},
			},
			TestStrategy: registry.TestStrategy{
				Endpoint: "https://sentry.io/api/0/organizations/",
			},
		},
		{
			Provider: "dropbox",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeDirectBrokered,
				Supported: []registry.RuntimeMode{registry.RuntimeDirectBrokered},
			},
			// Should NOT produce gateway routes.
		},
	}
}

func TestCompile_BuildsRoutes(t *testing.T) {
	router, err := route.Compile(testTemplates())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	routes := router.Routes()
	if len(routes) == 0 {
		t.Fatal("expected at least one route")
	}

	// Verify openrouter routes exist.
	rt, ok := router.Match("POST", "/api/openrouter/chat_completion")
	if !ok {
		t.Error("expected /api/openrouter/chat_completion route")
	}
	if ok && rt.Provider != "openrouter" {
		t.Errorf("expected provider=openrouter, got %q", rt.Provider)
	}

	// Verify sentry route exists.
	_, ok = router.Match("POST", "/api/sentry/error_reporting")
	if !ok {
		t.Error("expected /api/sentry/error_reporting route")
	}
}

func TestCompile_SDKRoutes(t *testing.T) {
	router, err := route.Compile(testTemplates())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// openrouter supports gateway_sdk, so SDK routes should be compiled.
	_, ok := router.Match("POST", "/sdk/openrouter/v1/chat_completion")
	if !ok {
		t.Error("expected SDK route /sdk/openrouter/v1/chat_completion")
	}
}

func TestMatch_UnknownPath_ReturnsNotFound(t *testing.T) {
	router, err := route.Compile(testTemplates())
	if err != nil {
		t.Fatal(err)
	}

	_, ok := router.Match("POST", "/api/unknown/action")
	if ok {
		t.Error("expected no match for unknown path")
	}
}

func TestMatch_DropboxExcluded(t *testing.T) {
	router, err := route.Compile(testTemplates())
	if err != nil {
		t.Fatal(err)
	}

	_, ok := router.Match("POST", "/api/dropbox/file_read")
	if ok {
		t.Error("dropbox (direct_brokered) should not produce gateway routes")
	}
}

func TestCompile_WithGatewayActions(t *testing.T) {
	templates := []registry.ConnectionTemplate{
		{
			Provider: "custom",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeGatewayTyped,
				Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
			},
			AuthPlacement: registry.AuthPlacement{In: "header", Name: "Authorization", Scheme: "Bearer"},
			GatewayActions: []registry.GatewayAction{
				{
					Name:             "send",
					ExchangeStrategy: registry.ExchangeStaticGatewayOnly,
					RiskLabel:        "destructive",
				},
				{
					Name:      "read",
					RiskLabel: "low",
				},
			},
			TestStrategy: registry.TestStrategy{
				Endpoint: "https://api.custom.com/v1",
			},
		},
	}

	router, err := route.Compile(templates)
	if err != nil {
		t.Fatal(err)
	}

	rt, ok := router.Match("POST", "/api/custom/send")
	if !ok {
		t.Error("expected /api/custom/send route")
	}
	// "destructive" risk label should set LLMSessionDeny.
	if ok && !rt.LLMSessionDeny {
		t.Error("destructive risk label should set LLMSessionDeny=true")
	}

	rt2, ok2 := router.Match("POST", "/api/custom/read")
	if !ok2 {
		t.Error("expected /api/custom/read route")
	}
	if ok2 && rt2.LLMSessionDeny {
		t.Error("low risk label should not set LLMSessionDeny")
	}
}

func TestCompile_UpstreamHostFromTestStrategy(t *testing.T) {
	templates := []registry.ConnectionTemplate{
		{
			Provider: "testprovider",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeGatewayTyped,
				Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
			},
			Capabilities: []registry.Capability{
				{Name: "action"},
			},
			TestStrategy: registry.TestStrategy{
				Endpoint: "https://api.testprovider.com/v1/endpoint",
			},
		},
	}

	router, err := route.Compile(templates)
	if err != nil {
		t.Fatal(err)
	}

	rt, ok := router.Match("POST", "/api/testprovider/action")
	if !ok {
		t.Fatal("expected route")
	}
	if rt.UpstreamHost != "api.testprovider.com" {
		t.Errorf("expected UpstreamHost=api.testprovider.com, got %q", rt.UpstreamHost)
	}
}

func TestCompile_UsesSDKPath(t *testing.T) {
	templates := []registry.ConnectionTemplate{
		{
			Provider: "openai",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeGatewaySDK,
				Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK},
			},
			GatewayActions: []registry.GatewayAction{
				{
					Name:         "chat_completion",
					SDKPath:      "/v1/chat/completions",
					Method:       "POST",
					UpstreamPath: "/v1/chat/completions",
				},
			},
			TestStrategy: registry.TestStrategy{
				Endpoint: "https://api.openai.com/v1/models",
			},
		},
	}

	router, err := route.Compile(templates)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// SDK route must use the declared sdk_path, not the synthesised fallback.
	rt, ok := router.Match("POST", "/v1/chat/completions")
	if !ok {
		t.Error("expected SDK route at /v1/chat/completions (from sdk_path)")
	}
	if ok && rt.SDKPath != "/v1/chat/completions" {
		t.Errorf("expected SDKPath=/v1/chat/completions, got %q", rt.SDKPath)
	}

	// Synthesised path must NOT be registered when sdk_path is explicitly set.
	_, fallbackOK := router.Match("POST", "/sdk/openai/v1/chat_completion")
	if fallbackOK {
		t.Error("fallback SDK path must not be registered when sdk_path is explicitly set")
	}
}

func TestCompile_UsesActionMethod(t *testing.T) {
	templates := []registry.ConnectionTemplate{
		{
			Provider: "openai",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeGatewaySDK,
				Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK},
			},
			GatewayActions: []registry.GatewayAction{
				{
					Name:    "model_listing",
					Method:  "GET",
					SDKPath: "/v1/models",
				},
			},
			TestStrategy: registry.TestStrategy{
				Endpoint: "https://api.openai.com/v1/models",
			},
		},
	}

	router, err := route.Compile(templates)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// GET /api/openai/model_listing must be registered.
	rt, ok := router.Match("GET", "/api/openai/model_listing")
	if !ok {
		t.Error("expected GET /api/openai/model_listing route")
	}
	if ok && rt.Method != "GET" {
		t.Errorf("expected Method=GET, got %q", rt.Method)
	}

	// POST must NOT match (different method).
	_, postOK := router.Match("POST", "/api/openai/model_listing")
	if postOK {
		t.Error("POST must not match a GET-only route")
	}
}

func TestCompile_FallbackSDKPath(t *testing.T) {
	templates := []registry.ConnectionTemplate{
		{
			Provider: "openrouter",
			RuntimeSupport: registry.RuntimeSupport{
				Preferred: registry.RuntimeGatewaySDK,
				Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK},
			},
			GatewayActions: []registry.GatewayAction{
				{
					Name: "chat_completion",
					// No SDKPath set: should fall back to /sdk/<provider>/v1/<name>.
				},
			},
			TestStrategy: registry.TestStrategy{
				Endpoint: "https://openrouter.ai/api/v1/models",
			},
		},
	}

	router, err := route.Compile(templates)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Fallback SDK path must be synthesised.
	_, ok := router.Match("POST", "/sdk/openrouter/v1/chat_completion")
	if !ok {
		t.Error("expected fallback SDK path /sdk/openrouter/v1/chat_completion when no sdk_path is set")
	}
}

// openaiLikeTemplate returns a synthetic ConnectionTemplate that mirrors the
// openai.yaml GatewayActions structure. This avoids a registry.Get() call
// which requires TestMain init, keeping the test self-contained.
func openaiLikeTemplate() registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: "openai",
		Category: "ai",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewaySDK,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewaySDK, registry.RuntimeGatewayTyped},
		},
		AuthPlacement: registry.AuthPlacement{In: "header", Name: "Authorization", Scheme: "Bearer"},
		GatewayActions: []registry.GatewayAction{
			{Name: "chat_completion", SDKPath: "/v1/chat/completions", Method: "POST", UpstreamPath: "/v1/chat/completions"},
			{Name: "responses", SDKPath: "/v1/responses", Method: "POST", UpstreamPath: "/v1/responses"},
			{Name: "embeddings", SDKPath: "/v1/embeddings", Method: "POST", UpstreamPath: "/v1/embeddings"},
			{Name: "model_listing", SDKPath: "/v1/models", Method: "GET", UpstreamPath: "/v1/models"},
		},
		InjectionRules: []registry.InjectionRule{{EnvVar: "OPENAI_API_KEY", Source: "api_key"}},
		TestStrategy: registry.TestStrategy{
			Endpoint: "https://api.openai.com/v1/models",
		},
	}
}

// TestSDKDriver_OpenAIChatCompletions_Routes verifies that the compiled route
// table for an openai-like template correctly registers SDK routes at the
// declared sdk_path values from GatewayActions, not at synthesised fallback paths.
//
// Mirrors the openai.yaml GatewayActions:
//   - sdk_path: /v1/chat/completions (POST)
//   - sdk_path: /v1/responses (POST)
//   - sdk_path: /v1/embeddings (POST)
//   - sdk_path: /v1/models (GET)
func TestSDKDriver_OpenAIChatCompletions_Routes(t *testing.T) {
	tmpl := openaiLikeTemplate()
	templates := []registry.ConnectionTemplate{tmpl}
	router, err := route.Compile(templates)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Verify each declared GatewayAction SDKPath is routed at the declared path.
	cases := []struct {
		method  string
		sdkPath string
		action  string
	}{
		{"POST", "/v1/chat/completions", "chat_completion"},
		{"POST", "/v1/responses", "responses"},
		{"POST", "/v1/embeddings", "embeddings"},
		{"GET", "/v1/models", "model_listing"},
	}
	for _, tc := range cases {
		rt, ok := router.Match(tc.method, tc.sdkPath)
		if !ok {
			t.Errorf("expected SDK route %s %s (GatewayAction %q)", tc.method, tc.sdkPath, tc.action)
			continue
		}
		if rt.SDKPath != tc.sdkPath {
			t.Errorf("route %s %s: SDKPath=%q, want %q", tc.method, tc.sdkPath, rt.SDKPath, tc.sdkPath)
		}
		if rt.Provider != "openai" {
			t.Errorf("route %s %s: Provider=%q, want openai", tc.method, tc.sdkPath, rt.Provider)
		}
	}

	// The synthesised fallback path must NOT be registered when sdk_path is set.
	_, fallbackOK := router.Match("POST", "/sdk/openai/v1/chat_completion")
	if fallbackOK {
		t.Error("synthesised fallback path must not be registered when sdk_path is explicitly declared")
	}

	// The typed /api/ path must also exist.
	rt, ok := router.Match("POST", "/api/openai/chat_completion")
	if !ok {
		t.Error("expected typed route /api/openai/chat_completion")
	}
	if ok && rt.Provider != "openai" {
		t.Errorf("expected provider=openai, got %q", rt.Provider)
	}
}
