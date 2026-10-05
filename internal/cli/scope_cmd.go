package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/spf13/cobra"
)

// newScopeCmd returns the `keylatch scope` command. Prints the support
// manifest (internal/manifest) — the single source of truth for which
// managers, runtimes, platforms, and features are supported, unavailable,
// or experimental in this build.
//
// CLI help/doctor, the web UI, and packaging are not yet fully wired to the
// manifest; this command is the first real consumer proving it loads and is
// usable end to end.
func newScopeCmd() *cobra.Command {
	var useJSON bool
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Show what Keylatch supports in this release (support manifest)",
		RunE: func(c *cobra.Command, _ []string) error {
			m := manifest.Current()
			if useJSON {
				b, err := json.Marshal(m)
				if err != nil {
					return fmt.Errorf("keylatch scope: marshal: %w", err)
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "CATEGORY\tID\tSTATUS\tNOTE\n")
			for _, e := range m.Entries {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Category, e.ID, e.Status, e.Note)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON")
	return cmd
}
