package cli

import "github.com/spf13/cobra"

// newBrokerCmd returns the top-level `broker` subcommand group (Epic 20).
// Exposes broker status, dry-run, and revoke subcommands.
func newBrokerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "broker",
		Short: "Inspect and manage the token broker cache",
		Long: `Inspect and manage the keylatch token broker cache.

The broker mediates credential exchanges between LLM sessions and registered
provider strategies (OAuth, AWS STS, GitHub App, etc.).

Subcommands operate on metadata only — no credential values are emitted.`,
	}
	cmd.AddCommand(newBrokerStatusCmd())
	cmd.AddCommand(newBrokerDryRunCmd())
	cmd.AddCommand(newBrokerRevokeCmd())
	return cmd
}
