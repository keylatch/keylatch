package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newExperimentalCmd returns the `keylatch experimental` subcommand.
// It is always visible (not gated) and lists all gated commands with their
// graduation milestone. When KEYLATCH_EXPERIMENTAL=1 is set, running
// `keylatch experimental <cmd>` delegates to the real command.
func newExperimentalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "experimental [command]",
		Short: "List or run experimental commands (not production-ready)",
		Long:  `No experimental commands are currently gated. Future betas will appear here when enabled with KEYLATCH_EXPERIMENTAL=1.`,
		RunE: func(c *cobra.Command, _ []string) error {
			fmt.Fprintln(c.OutOrStdout(), "No experimental commands are currently gated.")
			fmt.Fprintln(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout(), "Future betas will appear here when enabled with KEYLATCH_EXPERIMENTAL=1.")
			return nil
		},
	}
	return cmd
}

// registerExperimentalAliases wires gated commands as sub-commands of
// `keylatch experimental <cmd>` when KEYLATCH_EXPERIMENTAL=1. Each alias is a
// thin wrapper that delegates to the real command constructor so that flags and
// arguments are identical to the top-level form.
func registerExperimentalAliases(experimentalGroup *cobra.Command, root *cobra.Command) {
	if !isExperimentalEnabled() {
		return
	}
	// Find the real command in root and add it as a child of the experimental
	// group as well, giving users both `keylatch approve` and
	// `keylatch experimental approve` when the gate is open.
	names := make([]string, 0, len(experimentalCmds))
	for _, ec := range experimentalCmds {
		names = append(names, ec.name)
	}
	for _, name := range names {
		realCmd, _, err := root.Find([]string{name})
		if err != nil || realCmd == root {
			continue
		}
		experimentalGroup.AddCommand(realCmd)
	}
}
