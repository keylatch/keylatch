package regvalidate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/cmd/regvalidate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validTemplate = `
provider: test-provider
display_name: Test Provider
category: ai
secret_fields:
  - name: api_key
    required: true
    sensitive: true
auth_flow: api_key
storage_path_tpl: "{{.Namespace}}/ai/test-provider/{{.Account}}"
trust_level: 0
runtime_support:
  preferred: gateway_typed
injection_rules:
  - env_var: TEST_API_KEY
    source: api_key
redaction:
  - pattern: 'test-[A-Za-z0-9]{20,}'
    replacement: "****"
test_strategy:
  kind: http_get
  endpoint: https://api.test-provider.example/v1/check
  expect:
    status_code: 200
`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestValidateTemplatePath_ValidTemplate(t *testing.T) {
	path := writeTemp(t, validTemplate)
	err := regvalidate.ValidateTemplatePath(path)
	require.NoError(t, err)
}

func TestValidateTemplatePath_MissingRequiredField(t *testing.T) {
	// Missing trust_level
	const incomplete = `
provider: test-provider
display_name: Test Provider
category: ai
secret_fields:
  - name: api_key
    required: true
    sensitive: true
auth_flow: api_key
storage_path_tpl: "{{.Namespace}}/ai/test-provider/{{.Account}}"
runtime_support:
  preferred: gateway_typed
`
	path := writeTemp(t, incomplete)
	err := regvalidate.ValidateTemplatePath(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust_level")
}

func TestValidateTemplatePath_NonexistentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.yaml")
	err := regvalidate.ValidateTemplatePath(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot read file")
}

func TestValidateCmd_ValidTemplate(t *testing.T) {
	path := writeTemp(t, validTemplate)

	cmd := regvalidate.NewValidateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{path})

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "OK: "+path)
}

func TestValidateTemplatePath_TODOInNamedField(t *testing.T) {
	const withTODO = `
provider: test-provider
display_name: TODO Replace This
category: ai
secret_fields:
  - name: api_key
    required: true
    sensitive: true
auth_flow: api_key
storage_path_tpl: "{{.Namespace}}/ai/test-provider/{{.Account}}"
trust_level: 0
runtime_support:
  preferred: gateway_typed
`
	path := writeTemp(t, withTODO)
	err := regvalidate.ValidateTemplatePath(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TODO placeholder")
	assert.Contains(t, err.Error(), "display_name")
}

func TestValidateTemplatePath_BareTODO(t *testing.T) {
	// A TODO that is not on a named-field line triggers the bare-TODO fallback.
	const withBareTODO = `
provider: test-provider
display_name: Test Provider
category: ai
secret_fields:
  - name: api_key
    required: true
    sensitive: true
auth_flow: api_key
storage_path_tpl: "{{.Namespace}}/ai/test-provider/{{.Account}}"
trust_level: 0
runtime_support:
  preferred: gateway_typed
# TODO: fill in later
`
	path := writeTemp(t, withBareTODO)
	err := regvalidate.ValidateTemplatePath(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TODO placeholder")
	// The bare-TODO fallback returns "unknown" as the field name.
	assert.Contains(t, err.Error(), "unknown")
}
