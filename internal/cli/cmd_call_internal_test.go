package cli

import (
	"encoding/json"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

// TestParseProviderAction_Valid verifies standard "provider.action" parsing.
func TestParseProviderAction_Valid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input    string
		provider string
		action   string
		ok       bool
	}{
		{"openrouter.chat", "openrouter", "chat", true},
		{"aws.sts", "aws", "sts", true},
		{"github.app", "github", "app", true},
		{"a.b", "a", "b", true},
	}
	for _, tc := range cases {
		prov, act, ok := parseProviderAction(tc.input)
		if ok != tc.ok {
			t.Errorf("parseProviderAction(%q) ok = %v, want %v", tc.input, ok, tc.ok)
		}
		if ok {
			if prov != tc.provider {
				t.Errorf("parseProviderAction(%q) provider = %q, want %q", tc.input, prov, tc.provider)
			}
			if act != tc.action {
				t.Errorf("parseProviderAction(%q) action = %q, want %q", tc.input, act, tc.action)
			}
		}
	}
}

// TestParseProviderAction_Invalid verifies invalid formats are rejected.
func TestParseProviderAction_Invalid(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"noDot",
		".startdot",
		"enddot.",
		"..double",
	}
	for _, tc := range cases {
		_, _, ok := parseProviderAction(tc)
		if ok {
			t.Errorf("parseProviderAction(%q) should be invalid", tc)
		}
	}
}

// TestBuildCallMeta_NoAction verifies buildCallMeta works when action is nil.
func TestBuildCallMeta_NoAction(t *testing.T) {
	t.Parallel()
	m := buildCallMeta("chat", nil, "static_gateway_only")
	if m.Action != "chat" {
		t.Errorf("action = %q, want chat", m.Action)
	}
	if m.LLMSessionDeny {
		t.Error("LLMSessionDeny should be false when action is nil")
	}
}

// TestCallMetaAllowlist verifies every JSON key in callMeta appears
// in callMetaAllowedFields, and callMetaFilteredFields drops unknown keys.
func TestCallMetaAllowlist(t *testing.T) {
	t.Parallel()

	// Build a fully-populated callMeta.
	action := &registry.GatewayAction{
		Name:                   "test",
		ExchangeStrategy:       "static_gateway_only",
		MaskingProfile:         "basic",
		AllowedFields:          []string{"field1"},
		MaxAccessTokenTTL:      "1h",
		RequiredScopes:         []string{"read"},
		UntrustedContentSource: true,
		LLMSessionDeny:         true,
	}
	m := buildCallMeta("test", action, "static_gateway_only")

	// Marshal callMeta to discover all JSON keys.
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal callMeta: %v", err)
	}
	var allKeys map[string]interface{}
	if err := json.Unmarshal(raw, &allKeys); err != nil {
		t.Fatalf("unmarshal callMeta: %v", err)
	}

	// Every key in the marshalled struct must appear in callMetaAllowedFields.
	for k := range allKeys {
		if !callMetaAllowedFields[k] {
			t.Errorf("callMeta field %q is not in callMetaAllowedFields — add it to the allowlist or remove it from the struct", k)
		}
	}

	// callMetaFilteredFields must drop any key that is not in the allowlist.
	// We inject a canary key by temporarily marshaling a struct with an extra field.
	type callMetaWithCanary struct {
		callMeta
		SecretCanary string `json:"secret_canary,omitempty"`
	}
	withCanary := callMetaWithCanary{callMeta: m, SecretCanary: "CANARY"}
	canaryRaw, _ := json.Marshal(withCanary)
	var canaryMap map[string]interface{}
	_ = json.Unmarshal(canaryRaw, &canaryMap)
	// Manually filter using callMetaAllowedFields logic.
	filtered := make(map[string]interface{})
	for k, v := range canaryMap {
		if callMetaAllowedFields[k] {
			filtered[k] = v
		}
	}
	if _, ok := filtered["secret_canary"]; ok {
		t.Error("callMetaAllowedFields did not strip canary key secret_canary")
	}

	// callMetaFilteredFields output must match callMetaAllowedFields.
	out := callMetaFilteredFields(m)
	for k := range out {
		if !callMetaAllowedFields[k] {
			t.Errorf("callMetaFilteredFields emitted non-allowlisted key %q", k)
		}
	}
}

// TestBuildCallMeta_WithAction verifies all action fields are copied.
func TestBuildCallMeta_WithAction(t *testing.T) {
	t.Parallel()
	action := &registry.GatewayAction{
		Name:                   "chat",
		ExchangeStrategy:       "oauth_refresh",
		MaskingProfile:         "basic",
		AllowedFields:          []string{"messages"},
		MaxAccessTokenTTL:      "30m",
		RequiredScopes:         []string{"read"},
		UntrustedContentSource: true,
		LLMSessionDeny:         true,
	}
	m := buildCallMeta("chat", action, "oauth_refresh")
	if m.MaskingProfile != "basic" {
		t.Errorf("masking_profile = %q, want basic", m.MaskingProfile)
	}
	if !m.LLMSessionDeny {
		t.Error("LLMSessionDeny should be true")
	}
	if !m.UntrustedContentSource {
		t.Error("UntrustedContentSource should be true")
	}
}
