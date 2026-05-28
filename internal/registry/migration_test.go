package registry_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	providers "github.com/keylatch/keylatch/templates/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmbedTemplatesMatchOldRegistrations loads each core YAML via the EmbedLoader
// and asserts the resulting ConnectionTemplate contains the expected field values.
// This test guards against silent migration drift — it is the canonical parity check
// after providers_core_v1.go was deleted.
func TestEmbedTemplatesMatchOldRegistrations(t *testing.T) {
	loader := &registry.EmbedLoader{FS: providers.EmbeddedFS, Tier: registry.TierCore}
	loaded, err := loader.LoadAll(context.Background())
	require.NoError(t, err, "core YAML files must all load without error")

	bySlug := make(map[string]registry.ConnectionTemplate, len(loaded))
	for _, lt := range loaded {
		bySlug[lt.Template.Provider] = lt.Template
	}

	type expected struct {
		provider    string
		displayName string
		category    string
		authFlow    registry.AuthFlow
		preferred   registry.RuntimeMode
	}

	cases := []expected{
		{"openrouter", "OpenRouter", "ai", registry.AuthAPIKey, registry.RuntimeGatewaySDK},
		{"sentry", "Sentry", "observability", registry.AuthAPIKey, registry.RuntimeGatewayTyped},
		{"dropbox", "Dropbox", "storage", registry.AuthOAuthBrowser, registry.RuntimeDirectBrokered},
		{"cloudflare", "Cloudflare", "cdn", registry.AuthAPIKey, registry.RuntimeGatewayTyped},
		{"google_workspace", "Google Workspace", "workspace", registry.AuthOAuthBrowser, registry.RuntimeDirectBrokered},
	}

	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			tmpl, ok := bySlug[tc.provider]
			require.True(t, ok, "core YAML for %q must load successfully", tc.provider)

			assert.Equal(t, tc.provider, tmpl.Provider, "Provider")
			assert.Equal(t, tc.displayName, tmpl.DisplayName, "DisplayName")
			assert.Equal(t, tc.category, tmpl.Category, "Category")
			assert.Equal(t, tc.authFlow, tmpl.AuthFlow, "AuthFlow")
			assert.Equal(t, tc.preferred, tmpl.RuntimeSupport.Preferred, "RuntimeSupport.Preferred")
			assert.NotEmpty(t, tmpl.SecretFields, "SecretFields must not be empty")
			assert.NotEmpty(t, tmpl.InjectionRules, "InjectionRules must not be empty")
			assert.NotEmpty(t, tmpl.Redaction, "Redaction must not be empty")
			assert.NotEmpty(t, tmpl.TestStrategy.Kind, "TestStrategy.Kind must not be empty")
			assert.NotEmpty(t, tmpl.TestStrategy.Endpoint, "TestStrategy.Endpoint must not be empty")
		})
	}
}
