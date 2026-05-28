package registry_test

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/keylatch/keylatch/internal/registry"
	providers "github.com/keylatch/keylatch/templates/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validMinimalTemplate = `
provider: test-provider
display_name: Test Provider
category: test
description: A minimal valid test provider.
docs_url: https://example.com/docs

secret_fields:
  - name: api_key
    required: true
    sensitive: true

auth_flow: api_key
storage_path_tpl: "{{.Namespace}}/test/test-provider/{{.Account}}"
trust_level: 0

runtime_support:
  preferred: gateway_typed

test_strategy:
  kind: http_get
  endpoint: https://example.com/health
`

const schemaInvalidTemplate = `
provider: bad-provider
display_name: Bad Provider
category: test
# missing required fields: secret_fields, auth_flow, storage_path_tpl, trust_level
`

func TestEmbedLoader_ValidMinimal(t *testing.T) {
	memFS := fstest.MapFS{
		"test-provider.yaml": {Data: []byte(validMinimalTemplate)},
	}
	loader := &registry.EmbedLoader{FS: memFS, Tier: registry.TierCore}
	loaded, err := loader.LoadAll(context.Background())
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "test-provider", loaded[0].Template.Provider)
	assert.Equal(t, registry.SourceEmbed, loaded[0].Source)
	assert.Equal(t, registry.TierCore, loaded[0].Tier)
}

func TestEmbedLoader_SchemaInvalid(t *testing.T) {
	memFS := fstest.MapFS{
		"bad.yaml": {Data: []byte(schemaInvalidTemplate)},
	}
	loader := &registry.EmbedLoader{FS: memFS, Tier: registry.TierCore}
	_, err := loader.LoadAll(context.Background())
	require.Error(t, err, "schema-invalid template must return an error")
}

func TestValidateTemplateBytes_RejectsTODO(t *testing.T) {
	raw := []byte(`provider: test
display_name: Test
category: ai
description: "TODO: describe this provider."
docs_url: https://example.com
auth_flow: api_key
`)
	err := registry.ValidateTemplateBytes(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TODO")
}

func TestEmbedLoader_AllExistingYAML(t *testing.T) {
	loader := &registry.EmbedLoader{FS: providers.EmbeddedFS, Tier: registry.TierCore}
	loaded, err := loader.LoadAll(context.Background())
	require.NoError(t, err, "all existing YAML files in templates/providers/ must load without error")
	assert.NotEmpty(t, loaded, "expected at least one template to be loaded")
	for _, lt := range loaded {
		assert.NotEmpty(t, lt.Template.Provider, "provider slug must not be empty")
		assert.Equal(t, registry.SourceEmbed, lt.Source)
	}
}
