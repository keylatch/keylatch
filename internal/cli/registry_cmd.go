package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

// newRegistryListCmd returns the `registry list` subcommand.
// Outputs a tabwriter table of all registered provider templates.
// Flags: --category <cat>, --json.
func newRegistryListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered provider templates",
		RunE: func(c *cobra.Command, _ []string) error {
			cat, _ := c.Flags().GetString("category")
			jsonOut, _ := c.Root().PersistentFlags().GetBool("json")

			var templates []registry.ConnectionTemplate
			if cat != "" {
				templates = registry.ListByCategory(cat)
			} else {
				templates = registry.List()
			}

			if jsonOut {
				b, err := json.Marshal(templates)
				if err != nil {
					return err
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			// Tabwriter output.
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SLUG\tNAME\tCATEGORY\tAUTH_FLOW\tRUNTIME")
			for _, t := range templates {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					t.Provider,
					t.DisplayName,
					t.Category,
					string(t.AuthFlow),
					string(t.RuntimeSupport.Preferred),
				)
			}
			return w.Flush()
		},
	}
	cmd.Flags().String("category", "", "filter by category (e.g. ai, observability, storage)")
	return cmd
}

// newRegistryDescribeCmd returns the `registry describe <slug>` subcommand.
// Prints all non-secret fields of the ConnectionTemplate for <slug>.
func newRegistryDescribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "describe <slug>",
		Short: "Describe a provider template",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			slug := args[0]
			t, err := registry.Get(slug)
			if err != nil {
				if errors.Is(err, registry.ErrProviderNotFound) {
					fmt.Fprintf(c.ErrOrStderr(), "Error: provider %q not found\n", slug)
					return fmt.Errorf("provider %q not found", slug)
				}
				return err
			}

			jsonOut, _ := c.Root().PersistentFlags().GetBool("json")
			if jsonOut {
				b, merr := json.Marshal(t)
				if merr != nil {
					return merr
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			out := c.OutOrStdout()
			fmt.Fprintf(out, "Provider:    %s\n", t.Provider)
			fmt.Fprintf(out, "Name:        %s\n", t.DisplayName)
			fmt.Fprintf(out, "Category:    %s\n", t.Category)
			if t.Description != "" {
				fmt.Fprintf(out, "Description: %s\n", t.Description)
			}
			if t.DocsURL != "" {
				fmt.Fprintf(out, "Docs:        %s\n", t.DocsURL)
			}
			fmt.Fprintf(out, "Auth Flow:   %s\n", t.AuthFlow)
			fmt.Fprintf(out, "Runtime:     preferred=%s supported=[%s]\n",
				t.RuntimeSupport.Preferred,
				joinModes(t.RuntimeSupport.Supported))

			if len(t.SecretFields) > 0 {
				fmt.Fprintln(out, "\nSecret Fields:")
				for _, sf := range t.SecretFields {
					req := "optional"
					if sf.Required {
						req = "required"
					}
					fmt.Fprintf(out, "  %-20s  %-8s  %s\n", sf.Name, req, sf.Description)
				}
			}

			if len(t.AllowedCommandPrefixes) > 0 {
				fmt.Fprintf(out, "\nAllowed Prefixes: %s\n", strings.Join(t.AllowedCommandPrefixes, ", "))
			}

			if len(t.Capabilities) > 0 {
				fmt.Fprintln(out, "\nCapabilities:")
				for _, cap := range t.Capabilities {
					fmt.Fprintf(out, "  %-20s  %s\n", cap.Name, cap.Description)
				}
			}

			return nil
		},
	}
}

// joinModes returns a comma-joined string of RuntimeMode values.
func joinModes(modes []registry.RuntimeMode) string {
	s := make([]string, len(modes))
	for i, m := range modes {
		s[i] = string(m)
	}
	return strings.Join(s, ", ")
}

// newRegistryReloadCmd returns the `registry reload` subcommand.
// Re-runs InitFromConfig and prints the count of loaded templates.
func newRegistryReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Reload provider templates from embedded and local sources",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if err := registry.InitFromConfig(ctx, llmcontext.DefaultLookup); err != nil {
				return fmt.Errorf("registry reload: %w", err)
			}
			templates := registry.List()
			fmt.Fprintf(c.OutOrStdout(), "registry: loaded %d templates\n", len(templates))

			// Emit an audit log event for registry reload.
			registry.RegistryLoadHook(registry.RegistryLoadAuditEvent{
				Action:          registry.ActionRegistryLoad,
				SignatureStatus: registry.SignatureVerified,
			})
			return nil
		},
	}
}
