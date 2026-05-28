package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// schemaOnce guards one-time compilation of the provider template JSON schema.
var (
	schemaOnce       sync.Once
	compiledSchema   *jsonschema.Schema
	schemaCompileErr error
)

// compileSchema compiles the JSON schema embedded in the validate command
// package. We re-embed it here so embed_loader has no import cycle with
// internal/cmd/registry.
//
//go:generate echo "schema is embedded from templates/providers/schema.json via schemaBytes below"

// schemaBytes is filled by the test or at init time via the embedded schema.
// We rely on the schema.json checked in at templates/providers/schema.json and
// embedded by the validate command; here we embed it directly.
var embeddedSchemaBytes []byte // set by embedSchemaInit via init()

func init() {
	embeddedSchemaBytes = providerSchemaJSON
}

// getCompiledSchema returns (and lazily compiles) the provider template schema.
func getCompiledSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft7
		if err := compiler.AddResource(
			"https://keylatch.io/schemas/provider-template/v1",
			bytes.NewReader(embeddedSchemaBytes),
		); err != nil {
			schemaCompileErr = fmt.Errorf("registry: compile schema: %w", err)
			return
		}
		s, err := compiler.Compile("https://keylatch.io/schemas/provider-template/v1")
		if err != nil {
			schemaCompileErr = fmt.Errorf("registry: compile schema: %w", err)
			return
		}
		compiledSchema = s
	})
	return compiledSchema, schemaCompileErr
}

// ValidateTemplateBytes validates YAML bytes against the provider template JSON schema.
// It converts YAML → JSON-compatible Go value first, then validates the value directly
// using jsonschema/v5's Validate(interface{}) method.
// This is the canonical schema validator shared by EmbedLoader and the CLI validate command.
func ValidateTemplateBytes(yamlBytes []byte) error {
	return validateTemplateBytes(yamlBytes)
}

// validateTemplateBytes is the internal implementation of ValidateTemplateBytes.
func validateTemplateBytes(yamlBytes []byte) error {
	if bytes.Contains(yamlBytes, []byte("TODO")) {
		return fmt.Errorf("template contains TODO placeholder: replace all TODO fields before submitting")
	}

	schema, err := getCompiledSchema()
	if err != nil {
		return err
	}

	// Parse YAML into a generic Go value.
	var raw any
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return fmt.Errorf("invalid YAML: %w", err)
	}

	// yaml.v3 may produce map[string]any or map[any]any.
	// Normalize to JSON-compatible types by round-tripping through JSON,
	// then decode into a fresh any so the types match what jsonschema/v5 expects.
	jsonBytes, err := json.Marshal(normalizeYAML(raw))
	if err != nil {
		return fmt.Errorf("yaml→json conversion: %w", err)
	}

	var jsonVal any
	if err := json.Unmarshal(jsonBytes, &jsonVal); err != nil {
		return fmt.Errorf("json decode: %w", err)
	}

	if err := schema.Validate(jsonVal); err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}
	return nil
}

// normalizeYAML converts yaml.v3 decoded values (which can have map[string]any)
// to JSON-safe values. In practice gopkg.in/yaml.v3 already uses map[string]any,
// but we normalise recursively to be safe.
func normalizeYAML(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			out[k] = normalizeYAML(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			out[fmt.Sprintf("%v", k)] = normalizeYAML(vv)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, vv := range val {
			out[i] = normalizeYAML(vv)
		}
		return out
	default:
		return val
	}
}

// parseTemplate reads YAML bytes into a ConnectionTemplate.
func parseTemplate(yamlBytes []byte) (ConnectionTemplate, error) {
	var t ConnectionTemplate
	if err := yaml.Unmarshal(yamlBytes, &t); err != nil {
		return ConnectionTemplate{}, fmt.Errorf("unmarshal: %w", err)
	}
	return t, nil
}

// LoadAll implements Loader. It reads all *.yaml files from the embedded FS,
// validates each against the provider template schema, and returns them as
// LoadedTemplates with Source=SourceEmbed and the configured Tier.
// Returns an error if two files in the same FS share the same provider slug.
func (e *EmbedLoader) LoadAll(_ context.Context) ([]LoadedTemplate, error) {
	var results []LoadedTemplate
	seen := make(map[string]string) // slug → file path

	err := fs.WalkDir(e.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}

		data, err := fs.ReadFile(e.FS, p)
		if err != nil {
			return fmt.Errorf("read %q: %w", p, err)
		}

		if err := validateTemplateBytes(data); err != nil {
			return fmt.Errorf("template %q: %w", path.Base(p), err)
		}

		tmpl, err := parseTemplate(data)
		if err != nil {
			return fmt.Errorf("parse %q: %w", p, err)
		}

		if prev, ok := seen[tmpl.Provider]; ok {
			return fmt.Errorf("duplicate provider slug %q: found in %q and %q", tmpl.Provider, prev, p)
		}
		seen[tmpl.Provider] = p

		results = append(results, LoadedTemplate{
			Template: tmpl,
			Source:   SourceEmbed,
			Tier:     e.Tier,
			Path:     p,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}
