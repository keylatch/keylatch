package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/manifest"
)

type backendListEntry struct {
	ID   string `json:"id"`
	Tier string `json:"tier"`
	Note string `json:"note"`
}

// newBackendListCmd returns `keylatch backend list`: every secret backend
// with its support tier, read from the support manifest.
func newBackendListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secret backends and their support tier",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			entries := manifest.Current().ByCategory(manifest.CategoryManager)
			rows := make([]backendListEntry, 0, len(entries))
			for _, e := range entries {
				rows = append(rows, backendListEntry{ID: e.ID, Tier: string(e.Status), Note: e.Note})
			}
			if asJSON {
				enc := json.NewEncoder(c.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTIER\tNOTE")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.ID, r.Tier, r.Note)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output as JSON")
	return cmd
}
