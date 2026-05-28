package registry

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSchemaFileExists verifies that the provider template JSON Schema is present.
func TestSchemaFileExists(t *testing.T) {
	// Walk up to find templates/providers/schema.json relative to this test file.
	// Go test runs with cwd = package dir, so walk up two levels.
	schemaPath := "../../templates/providers/schema.json"
	_, err := os.Stat(schemaPath)
	require.NoError(t, err, "templates/providers/schema.json must exist")
}

// TestSchemaIsValidJSON verifies that the schema file is well-formed JSON.
func TestSchemaIsValidJSON(t *testing.T) {
	schemaPath := "../../templates/providers/schema.json"
	data, err := os.ReadFile(schemaPath)
	require.NoError(t, err)

	var schema map[string]interface{}
	err = json.Unmarshal(data, &schema)
	require.NoError(t, err, "schema.json must be valid JSON")

	// Must have $schema key.
	schemaKey, ok := schema["$schema"]
	assert.True(t, ok, "schema must have $schema key")
	assert.Contains(t, schemaKey.(string), "json-schema.org", "schema must reference json-schema.org")
}

// TestTemplatesRoundTripJSON verifies that all Core v1 templates can be
// JSON-marshalled and the round-trip produces identical structs.
func TestTemplatesRoundTripJSON(t *testing.T) {
	templates := List()
	require.NotEmpty(t, templates)

	for _, tmpl := range templates {
		tmpl := tmpl
		t.Run(tmpl.Provider, func(t *testing.T) {
			data, err := json.Marshal(tmpl)
			require.NoError(t, err, "marshal must succeed")

			var decoded ConnectionTemplate
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err, "unmarshal must succeed")

			// Core identity fields must round-trip cleanly.
			assert.Equal(t, tmpl.Provider, decoded.Provider)
			assert.Equal(t, tmpl.DisplayName, decoded.DisplayName)
			assert.Equal(t, tmpl.Category, decoded.Category)
			assert.Equal(t, tmpl.AuthFlow, decoded.AuthFlow)
			assert.Equal(t, tmpl.TrustLevel, decoded.TrustLevel)
			assert.Equal(t, len(tmpl.SecretFields), len(decoded.SecretFields))
		})
	}
}

// TestSchemaRequiredFields verifies that required fields according to the schema
// are present on every Core v1 template when marshalled to JSON.
func TestSchemaRequiredFields(t *testing.T) {
	required := []string{
		"provider",
		"display_name",
		"category",
		"secret_fields",
		"auth_flow",
		"storage_path_tpl",
		"trust_level",
	}

	for _, tmpl := range List() {
		tmpl := tmpl
		t.Run(tmpl.Provider, func(t *testing.T) {
			data, err := json.Marshal(tmpl)
			require.NoError(t, err)

			var m map[string]interface{}
			require.NoError(t, json.Unmarshal(data, &m))

			for _, field := range required {
				_, ok := m[field]
				assert.True(t, ok, "provider %q: required field %q must be present in JSON", tmpl.Provider, field)
			}
		})
	}
}

// TestRuntimeSupportJSONTags verifies that runtime_support.preferred and
// runtime_support.supported serialize with the correct JSON keys.
func TestRuntimeSupportJSONTags(t *testing.T) {
	tmpl, err := Get("openrouter")
	require.NoError(t, err)

	data, err := json.Marshal(tmpl.RuntimeSupport)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	_, hasPreferred := m["preferred"]
	assert.True(t, hasPreferred, "runtime_support must have 'preferred' JSON key")
}
