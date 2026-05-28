package registry

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCoreV1TemplatesRequiredFields verifies that all Core v1 templates have
// required fields set and well-formed values.
func TestCoreV1TemplatesRequiredFields(t *testing.T) {
	templates := List()
	require.NotEmpty(t, templates, "Core v1 templates must be registered")

	for _, tmpl := range templates {
		tmpl := tmpl
		t.Run(tmpl.Provider, func(t *testing.T) {
			// Required fields must be non-empty.
			assert.NotEmpty(t, tmpl.Provider, "provider slug must be non-empty")
			assert.NotEmpty(t, tmpl.DisplayName, "display_name must be non-empty")
			assert.NotEmpty(t, tmpl.Category, "category must be non-empty")
			assert.NotEmpty(t, tmpl.AuthFlow, "auth_flow must be non-empty")
			assert.NotEmpty(t, tmpl.StoragePathTpl, "storage_path_tpl must be non-empty")

			// At least one secret field.
			require.NotEmpty(t, tmpl.SecretFields, "secret_fields must not be empty")

			// TestStrategy endpoint must parse as a URL for non-sdk_call strategies.
			// sdk_call endpoints may contain tenant-scoped template variables (e.g. {domain})
			// which are not valid RFC-3986 URLs; those are validated at runtime.
			if tmpl.TestStrategy.Endpoint != "" && tmpl.TestStrategy.Kind != "sdk_call" {
				_, err := url.ParseRequestURI(tmpl.TestStrategy.Endpoint)
				assert.NoError(t, err, "test_strategy.endpoint must be a valid URL, got %q", tmpl.TestStrategy.Endpoint)
			}

			// EnvMappings must be non-empty when any SecretField has EnvVar set.
			for _, sf := range tmpl.SecretFields {
				if sf.EnvVar != "" {
					assert.NotEmpty(t, tmpl.EnvMappings, "env_mappings must be non-empty when secret_field.env_var is set")
					_, ok := tmpl.EnvMappings[sf.Name]
					assert.True(t, ok, "env_mappings must contain key %q matching secret field name", sf.Name)
				}
			}

			// Redaction patterns must compile as valid regex.
			for _, r := range tmpl.Redaction {
				_, err := regexp.Compile(r.Pattern)
				assert.NoError(t, err, "redaction pattern %q must be a valid regex", r.Pattern)
			}
		})
	}
}

// TestRuntimeSupportContainsOnlyValidModes asserts S3-15(b): no deprecated
// RuntimeMode values appear in RuntimeSupport.Supported.
func TestRuntimeSupportContainsOnlyValidModes(t *testing.T) {
	for _, tmpl := range List() {
		for _, mode := range tmpl.RuntimeSupport.Supported {
			assert.True(t, IsValidRuntimeMode(mode),
				"provider %q: RuntimeSupport.Supported contains invalid mode %q", tmpl.Provider, mode)
		}
		assert.True(t, IsValidRuntimeMode(tmpl.RuntimeSupport.Preferred),
			"provider %q: RuntimeSupport.Preferred is invalid mode %q", tmpl.Provider, tmpl.RuntimeSupport.Preferred)
	}
}

// TestCatalogGetReturnsNotFound verifies that Get returns ErrProviderNotFound for unknown providers.
func TestCatalogGetReturnsNotFound(t *testing.T) {
	_, err := Get("nonexistent-provider-xyz")
	assert.ErrorIs(t, err, ErrProviderNotFound)
}

// TestCatalogGetKnownProviders verifies that all Core v1 providers can be retrieved.
func TestCatalogGetKnownProviders(t *testing.T) {
	providers := []string{"openrouter", "sentry", "dropbox", "cloudflare", "google_workspace"}
	for _, p := range providers {
		tmpl, err := Get(p)
		require.NoError(t, err, "Get(%q) must succeed", p)
		assert.Equal(t, p, tmpl.Provider)
	}
}

// TestCatalogListByCategory verifies category filtering.
func TestCatalogListByCategory(t *testing.T) {
	aiTemplates := ListByCategory("ai")
	require.NotEmpty(t, aiTemplates, "should have at least one AI provider")
	for _, tmpl := range aiTemplates {
		assert.Equal(t, "ai", tmpl.Category)
	}
}

// TestGetTrustLevel verifies trust level lookup.
func TestGetTrustLevel(t *testing.T) {
	level, err := GetTrustLevel("openrouter")
	require.NoError(t, err)
	assert.Equal(t, TrustCore, level)
}

// TestGetTrustLevelNotFound verifies ErrProviderNotFound on unknown provider.
func TestGetTrustLevelNotFound(t *testing.T) {
	_, err := GetTrustLevel("unknown-provider")
	assert.ErrorIs(t, err, ErrProviderNotFound)
}

// TestBackwardCompatFieldsDerived verifies that DefaultRuntime, RuntimeReason,
// and GatewaySupported are correctly derived from RuntimeSupport.Preferred.
func TestBackwardCompatFieldsDerived(t *testing.T) {
	tests := []struct {
		provider    string
		wantGateway bool
	}{
		{"openrouter", true},        // preferred: gateway_sdk
		{"sentry", true},            // preferred: gateway_typed
		{"cloudflare", true},        // preferred: gateway_typed
		{"dropbox", false},          // preferred: direct_brokered
		{"google_workspace", false}, // preferred: direct_brokered
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.provider, func(t *testing.T) {
			tmpl, err := Get(tc.provider)
			require.NoError(t, err)
			assert.Equal(t, tc.wantGateway, tmpl.RuntimeSupport.GatewaySupported,
				"provider %q: GatewaySupported mismatch", tc.provider)
			assert.Equal(t, tmpl.RuntimeSupport.Preferred, tmpl.RuntimeSupport.DefaultRuntime,
				"DefaultRuntime must equal Preferred")
			assert.NotEmpty(t, tmpl.RuntimeSupport.RuntimeReason)
		})
	}
}

// TestProviderTemplates_HasExpectedActions verifies that the headline AI providers
// ship with the minimum set of actions required by EPIC-20.
func TestProviderTemplates_HasExpectedActions(t *testing.T) {
	cases := []struct {
		provider       string
		requiredAction string
	}{
		{"openai", "list-models"},
		{"openai", "list-files"},
		{"anthropic", "list-models"},
		{"openrouter", "list-models"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.provider+"/"+tc.requiredAction, func(t *testing.T) {
			t.Parallel()
			tmpl, err := Get(tc.provider)
			require.NoError(t, err, "provider %q must be registered", tc.provider)
			require.NotNil(t, tmpl.Actions, "provider %q: Actions map must not be nil", tc.provider)
			action, ok := tmpl.Actions[tc.requiredAction]
			assert.True(t, ok, "provider %q: must have action %q", tc.provider, tc.requiredAction)
			assert.NotEmpty(t, action.Method, "action %q: Method must not be empty", tc.requiredAction)
			assert.NotEmpty(t, action.Path, "action %q: Path must not be empty", tc.requiredAction)
		})
	}
}

// TestListReturnsSortedStableCopy verifies that List() returns templates in
// consistent alphabetical order across calls.
func TestListReturnsSortedStableCopy(t *testing.T) {
	list1 := List()
	list2 := List()
	require.Equal(t, len(list1), len(list2), "successive List() calls must return same count")
	for i := range list1 {
		assert.Equal(t, list1[i].Provider, list2[i].Provider,
			"List() must return stable order at index %d", i)
	}
	// Verify sorted.
	for i := 1; i < len(list1); i++ {
		assert.Less(t, list1[i-1].Provider, list1[i].Provider,
			"List() must be sorted; %q >= %q at indices %d/%d",
			list1[i-1].Provider, list1[i].Provider, i-1, i)
	}
}
