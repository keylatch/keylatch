package registry

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const providersRoot = "../../templates/providers"

// TestAllProviderTemplatesValidateAgainstSchema walks all *.yaml files under
// templates/providers/ (except embed.go and experimental/) and validates each
// against the schema. Must find at least 5 templates.
func TestAllProviderTemplatesValidateAgainstSchema(t *testing.T) {
	count := 0
	err := filepath.WalkDir(providersRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(filepath.ToSlash(p), "/experimental/") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		if verr := validateTemplateBytes(data); verr != nil {
			t.Errorf("template %q fails schema validation: %v", p, verr)
		}
		count++
		return nil
	})
	require.NoError(t, err, "WalkDir must not fail")
	assert.GreaterOrEqual(t, count, 5, "must find at least 5 provider templates, found %d", count)
}

// TestNoTemplateContainsTODOInCoreOrSaaS reads raw bytes of every YAML under
// templates/providers/core/ and templates/providers/saas/ and asserts none
// contain the string "TODO".
func TestNoTemplateContainsTODOInCoreOrSaaS(t *testing.T) {
	roots := []string{
		filepath.Join(providersRoot, "core"),
		filepath.Join(providersRoot, "saas"),
	}

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue // directory may not exist yet
			}
			require.NoError(t, err)
		}
		if !info.IsDir() {
			continue
		}

		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
				return nil
			}

			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}

			if bytes.Contains(data, []byte("TODO")) {
				t.Errorf("template %q contains TODO", p)
			}
			return nil
		})
		require.NoError(t, err, "WalkDir over %q must not fail", root)
	}
}

// TestProviderCapabilitiesAreDotCase checks that every capability name
// matches ^[a-z]([a-z0-9.]*[a-z0-9])?$ (dot-case, no underscores, no uppercase,
// no trailing dots).
func TestProviderCapabilitiesAreDotCase(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z]([a-z0-9.]*[a-z0-9])?$`)

	err := filepath.WalkDir(providersRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		var tmpl ConnectionTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil // schema validation handles parse errors
		}

		for _, cap := range tmpl.Capabilities {
			if !pattern.MatchString(cap.Name) {
				t.Errorf("template %q: capability name %q does not match ^[a-z]([a-z0-9.]*[a-z0-9])?$ (use dot-case, no trailing dots, no underscores)", p, cap.Name)
			}
		}
		return nil
	})
	require.NoError(t, err)
}

// TestProviderEnvVarsAreUniqueWithinTemplate asserts no env_var value is
// duplicated within a single template (across secret_fields and injection_rules).
func TestProviderEnvVarsAreUniqueWithinTemplate(t *testing.T) {
	err := filepath.WalkDir(providersRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		var tmpl ConnectionTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil
		}

		seen := make(map[string]string) // env_var -> source (field name or "injection_rules")

		for _, sf := range tmpl.SecretFields {
			if sf.EnvVar == "" {
				continue
			}
			if prev, ok := seen[sf.EnvVar]; ok {
				t.Errorf("template %q: env_var %q duplicated (first seen in %q)", p, sf.EnvVar, prev)
			}
			seen[sf.EnvVar] = "secret_fields[" + sf.Name + "]"
		}

		for _, ir := range tmpl.InjectionRules {
			if ir.EnvVar == "" {
				continue
			}
			// injection_rules referencing the same env_var as a secret_field is intentional;
			// only flag duplicates within the same category or truly repeated entries.
			if prev, ok := seen[ir.EnvVar]; ok && strings.HasPrefix(prev, "injection_rules") {
				t.Errorf("template %q: injection_rules env_var %q duplicated", p, ir.EnvVar)
			}
			seen[ir.EnvVar] = "injection_rules[" + ir.Source + "]"
		}
		return nil
	})
	require.NoError(t, err)
}

// TestInjectionRulesMatchSecretFields verifies that injection_rules and
// secret_fields are consistent within each provider template:
//   - Every secret_field with a non-empty env_var has a corresponding
//     injection_rules entry where source == secret_field.name.
//   - Every injection_rules[].source maps to an existing secret_field.name.
//
// Experimental templates are excluded.
func TestInjectionRulesMatchSecretFields(t *testing.T) {
	err := filepath.WalkDir(providersRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip the experimental/ subtree entirely.
		if strings.Contains(filepath.ToSlash(p), "/experimental/") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		var tmpl ConnectionTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil // schema validation handles parse errors
		}

		// Build a map of injection_rules sources for quick lookup.
		injectionSources := make(map[string]struct{}, len(tmpl.InjectionRules))
		for _, ir := range tmpl.InjectionRules {
			injectionSources[ir.Source] = struct{}{}
		}

		// Build a map of secret_field names for reverse lookup.
		secretFieldNames := make(map[string]struct{}, len(tmpl.SecretFields))
		for _, sf := range tmpl.SecretFields {
			secretFieldNames[sf.Name] = struct{}{}
		}

		// Every secret_field with a non-empty env_var must have a matching
		// injection_rules entry.
		for _, sf := range tmpl.SecretFields {
			if sf.EnvVar == "" {
				continue
			}
			if _, ok := injectionSources[sf.Name]; !ok {
				t.Errorf("template %q: secret_field %q (env_var=%q) has no corresponding injection_rules entry", p, sf.Name, sf.EnvVar)
			}
		}

		// Every injection_rules source must reference an existing secret_field.
		for _, ir := range tmpl.InjectionRules {
			if _, ok := secretFieldNames[ir.Source]; !ok {
				t.Errorf("template %q: injection_rules source %q does not match any secret_field name", p, ir.Source)
			}
		}

		return nil
	})
	require.NoError(t, err)
}

// TestProviderSecretKindNeverPrintsValue asserts that any secret_field with
// secret_kind == "service_account_json" has sensitive == true.
func TestProviderSecretKindNeverPrintsValue(t *testing.T) {
	err := filepath.WalkDir(providersRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		var tmpl ConnectionTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil
		}

		for _, sf := range tmpl.SecretFields {
			if sf.SecretKind == "service_account_json" && !sf.Sensitive {
				t.Errorf("template %q: field %q has secret_kind=service_account_json but sensitive=false; must be sensitive=true", p, sf.Name)
			}
		}
		return nil
	})
	require.NoError(t, err)
}
