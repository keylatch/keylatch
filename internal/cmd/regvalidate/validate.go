// Package regvalidate provides CLI commands for managing provider registry templates.
package regvalidate

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

//go:embed schema.json
var schemaJSON []byte //nolint:unused // retained for documentation and build-time embedding verification.

// NewValidateCmd returns a new `registry validate <path>` cobra command.
// A constructor is used instead of a package-level var so that concurrent
// tests can each build independent command trees without sharing cobra
// Command state (e.g. the parent pointer written by AddCommand).
func NewValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <path>",
		Short: "Validate a provider template YAML file against the provider schema",
		Args:  cobra.ExactArgs(1),
		RunE:  runValidate,
	}
}

func runValidate(c *cobra.Command, args []string) error {
	path := args[0]
	if err := ValidateTemplatePath(path); err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(c.OutOrStdout(), "OK: %s\n", path)
	return nil
}

// ValidateTemplatePath reads and validates a provider template YAML file at path.
// It applies the full JSON schema validation (the same schema used by EmbedLoader)
// and additionally rejects templates that contain TODO placeholder markers.
func ValidateTemplatePath(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read file %q: %w", path, err)
	}

	// Reject templates that still contain TODO markers — these indicate scaffolded
	// placeholders that must be replaced before the template can be submitted.
	if todoField := findTODOField(string(data)); todoField != "" {
		return fmt.Errorf("validation error: template contains TODO placeholder in field %q — replace all TODO markers before submitting", todoField)
	}

	if err := registry.ValidateTemplateBytes(data); err != nil {
		return fmt.Errorf("%q failed schema validation: %w", path, err)
	}

	return nil
}

// findTODOField returns the name of the first YAML field containing "TODO",
// or "" if none is found.
func findTODOField(content string) string {
	checkFields := []string{
		"display_name", "category", "description", "docs_url",
		"credentials_url", "capabilities", "endpoint",
	}
	for _, field := range checkFields {
		// Look for "field: ..TODO.." patterns in the YAML.
		prefix := field + ":"
		for _, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, prefix) && strings.Contains(trimmed, "TODO") {
				return field
			}
		}
	}
	// Also catch bare TODO anywhere in the file.
	if strings.Contains(content, "TODO") {
		return "unknown"
	}
	return ""
}
