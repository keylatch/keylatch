package route_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/gateway/route"
	"github.com/keylatch/keylatch/internal/registry"
)

func TestCompile_SupportedListEnablesGatewayAndSDK(t *testing.T) {
	tmpl := registry.ConnectionTemplate{
		Provider: "mixed",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeDirectBrokered,
			Supported: []registry.RuntimeMode{registry.RuntimeDirectBrokered, registry.RuntimeGatewaySDK},
		},
		InjectionRules: []registry.InjectionRule{{EnvVar: "MIXED_KEY", Source: "api_key"}},
		GatewayActions: []registry.GatewayAction{
			{Name: "search", UntrustedContentSource: true},
		},
		TestStrategy: registry.TestStrategy{Endpoint: "https://api.mixed.test/v2/ping"},
	}
	r, err := route.Compile([]registry.ConnectionTemplate{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	rt, ok := r.Match("POST", "/api/mixed/search")
	if !ok {
		t.Fatal("typed route missing")
	}
	if rt.UntrustedContentSource != "mixed" {
		t.Errorf("UntrustedContentSource = %q", rt.UntrustedContentSource)
	}
	if rt.SecretRef != "default/ai/mixed/api_key" {
		t.Errorf("SecretRef = %q, want default category ai", rt.SecretRef)
	}
	if rt.UpstreamHost != "api.mixed.test" || rt.UpstreamPath != "/v2/ping" {
		t.Errorf("upstream = %q %q", rt.UpstreamHost, rt.UpstreamPath)
	}
	sdk, ok := r.Match("POST", "/sdk/mixed/v1/search")
	if !ok || sdk.SDKPath != "/sdk/mixed/v1/search" {
		t.Fatalf("sdk route missing: %+v", sdk)
	}
}

func TestCompile_EndpointParsingFailuresYieldEmptyHost(t *testing.T) {
	for name, endpoint := range map[string]string{
		"empty":   "",
		"invalid": "https://bad host/%zz",
	} {
		t.Run(name, func(t *testing.T) {
			tmpl := registry.ConnectionTemplate{
				Provider:       "p",
				Category:       "observability",
				RuntimeSupport: registry.RuntimeSupport{Preferred: registry.RuntimeGatewayTyped},
				InjectionRules: []registry.InjectionRule{{Source: "token"}},
				Capabilities:   []registry.Capability{{Name: "logs send"}},
				TestStrategy:   registry.TestStrategy{Endpoint: endpoint},
			}
			r, err := route.Compile([]registry.ConnectionTemplate{tmpl})
			if err != nil {
				t.Fatal(err)
			}
			rt, ok := r.Match("POST", "/api/p/logs_send")
			if !ok {
				t.Fatal("synthesised route missing")
			}
			if rt.UpstreamHost != "" || rt.UpstreamPath != "" {
				t.Errorf("upstream = %q %q, want empty", rt.UpstreamHost, rt.UpstreamPath)
			}
			if rt.SecretRef != "default/observability/p/token" {
				t.Errorf("SecretRef = %q", rt.SecretRef)
			}
		})
	}
}

func TestCompile_NoInjectionRulesMeansNoSecretRef(t *testing.T) {
	tmpl := registry.ConnectionTemplate{
		Provider:       "bare",
		RuntimeSupport: registry.RuntimeSupport{Preferred: registry.RuntimeGatewayProxy},
		GatewayActions: []registry.GatewayAction{{Name: "wire", RiskLabel: "financial"}},
	}
	r, err := route.Compile([]registry.ConnectionTemplate{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	rt, ok := r.Match("POST", "/api/bare/wire")
	if !ok {
		t.Fatal("route missing")
	}
	if rt.SecretRef != "" {
		t.Errorf("SecretRef = %q, want empty", rt.SecretRef)
	}
	if !rt.LLMSessionDeny {
		t.Error("financial risk label must deny LLM sessions")
	}
}
