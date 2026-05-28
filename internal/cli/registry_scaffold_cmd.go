package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var categoryPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// scaffoldTmplText is the Go text/template used to generate a scaffolded YAML file.
// Note: StoragePathTpl is pre-formatted so curly braces don't conflict with
// Go's text/template delimiters.
const scaffoldTmplText = `provider: {{.Provider}}
display_name: {{.DisplayName}}
category: {{.Category}}
description: "TODO: describe this provider."
docs_url: https://TODO-docs-url.example.com
docs:
  credentials_url: https://TODO-credentials-url.example.com
{{if .Fields}}
secret_fields:
{{- range .Fields}}
  - name: {{.Name}}
    label: {{.Label}}
    required: true
    sensitive: true
    env_var: {{.EnvVar}}
    secret_kind: {{.SecretKind}}
{{- end}}

env_mappings:
{{- range .Fields}}
  {{.Name}}: {{.EnvVar}}
{{- end}}
{{end}}
auth_flow: {{.AuthFlow}}

storage_path_tpl: "{{.StoragePathTpl}}"
trust_level: 1

runtime_support:
  preferred: gateway_typed
  supported:
    - gateway_typed

capabilities:
  - name: TODO.capability
    description: TODO capability description

allowed_command_prefixes:
  - "node "
{{if .Fields}}
injection_rules:
{{- range .Fields}}
  - env_var: {{.EnvVar}}
    source: {{.Name}}
{{- end}}
{{end}}
test_strategy:
  kind: http_get
  endpoint: {{if .ValidateURL}}{{.ValidateURL}}{{else}}https://TODO-validate-endpoint.example.com/health{{end}}
  expect:
    status_code: 200
`

// scaffoldField holds parsed field data for template rendering.
type scaffoldField struct {
	Name       string
	Label      string
	EnvVar     string
	SecretKind string
}

// scaffoldData holds the data passed to the scaffold template.
type scaffoldData struct {
	Provider       string
	DisplayName    string
	Category       string
	AuthFlow       string
	StoragePathTpl string
	Fields         []scaffoldField
	ValidateURL    string
}

// parseFieldFlag parses a --field flag value of the form "name:ENV_VAR:secret_kind".
// The secret_kind component is optional.
func parseFieldFlag(s string) (scaffoldField, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 {
		return scaffoldField{}, fmt.Errorf("--field %q: expected format name:ENV_VAR[:secret_kind]", s)
	}
	name := strings.TrimSpace(parts[0])
	envVar := strings.TrimSpace(parts[1])
	kind := "api_key"
	if len(parts) == 3 {
		kind = strings.TrimSpace(parts[2])
	}
	if name == "" || envVar == "" {
		return scaffoldField{}, fmt.Errorf("--field %q: name and env_var must not be empty", s)
	}
	words := strings.Fields(strings.ReplaceAll(name, "_", " "))
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	label := strings.Join(words, " ")
	return scaffoldField{Name: name, Label: label, EnvVar: envVar, SecretKind: kind}, nil
}

// toDisplayName converts a provider slug to a display name.
// e.g. "my-provider" → "My Provider"
func toDisplayName(slug string) string {
	words := strings.FieldsFunc(slug, func(r rune) bool { return r == '-' || r == '_' })
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// newRegistryScaffoldCmd returns the `registry scaffold <slug>` subcommand.
// It generates a scaffolded YAML provider template under templates/providers/experimental/.
func newRegistryScaffoldCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scaffold <slug>",
		Short: "Scaffold a new provider template YAML",
		Long: `Scaffold generates a starter provider template YAML at
templates/providers/experimental/<slug>.yaml.

The generated file contains TODO markers for fields that must be filled in
before the template can be used in core/ or saas/. Replace all TODO markers in
the generated file before running keylatch registry validate.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			slug := args[0]
			if !slugPattern.MatchString(slug) {
				return fmt.Errorf("scaffold: slug %q is invalid; must match ^[a-z][a-z0-9-]{0,62}$", slug)
			}
			category, _ := c.Flags().GetString("category")
			if !categoryPattern.MatchString(category) {
				return fmt.Errorf("scaffold: category %q is invalid; must match ^[a-z][a-z0-9-]*$", category)
			}
			authFlow, _ := c.Flags().GetString("auth-flow")
			fieldFlags, _ := c.Flags().GetStringArray("field")
			validateURL, _ := c.Flags().GetString("validate-url")
			outDirOverride, _ := c.Flags().GetString("out-dir")

			// Parse field flags.
			var fields []scaffoldField
			for _, f := range fieldFlags {
				sf, err := parseFieldFlag(f)
				if err != nil {
					return err
				}
				fields = append(fields, sf)
			}

			// Build storage path template string (pre-formatted, not a Go template).
			storagePathTpl := fmt.Sprintf("{{.Namespace}}/%s/%s/{{.Account}}", category, slug)

			data := scaffoldData{
				Provider:       slug,
				DisplayName:    toDisplayName(slug),
				Category:       category,
				AuthFlow:       authFlow,
				StoragePathTpl: storagePathTpl,
				Fields:         fields,
				ValidateURL:    validateURL,
			}

			// Determine output path.
			outDir := filepath.Join("templates", "providers", "experimental")
			if outDirOverride != "" {
				outDir = outDirOverride
			}
			if err := os.MkdirAll(outDir, 0o750); err != nil {
				return fmt.Errorf("scaffold: create dir %q: %w", outDir, err)
			}
			outPath := filepath.Join(outDir, slug+".yaml")

			// Warn if not run from the repo root (templates/providers/ missing).
			if _, err := os.Stat(filepath.Join("templates", "providers")); os.IsNotExist(err) {
				fmt.Fprintf(c.ErrOrStderr(), "warning: 'templates/providers/' not found in current directory — run scaffold from the repo root\n")
			}

			// Render template.
			tmpl, err := template.New("scaffold").Parse(scaffoldTmplText)
			if err != nil {
				return fmt.Errorf("scaffold: parse template: %w", err)
			}

			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("scaffold: create %q: %w", outPath, err)
			}

			if err := tmpl.Execute(f, data); err != nil {
				_ = f.Close()
				return fmt.Errorf("scaffold: render template: %w", err)
			}

			if err := f.Close(); err != nil {
				return fmt.Errorf("scaffold: close %q: %w", outPath, err)
			}

			fmt.Fprintf(c.OutOrStdout(), "scaffold: wrote %s\n", outPath)
			return nil
		},
	}

	cmd.Flags().String("category", "", "provider category (required), e.g. communication, ai, payments")
	_ = cmd.MarkFlagRequired("category")
	cmd.Flags().String("auth-flow", "api_key", "authentication flow: api_key, bearer, basic, oauth_browser")
	cmd.Flags().StringArray("field", nil, "secret field in format name:ENV_VAR[:secret_kind] (repeatable)")
	cmd.Flags().String("validate-url", "", "URL to use for test_strategy endpoint")
	cmd.Flags().String("out-dir", "", "override output base directory (default: templates/providers/experimental)")
	_ = cmd.Flags().MarkHidden("out-dir")

	return cmd
}
