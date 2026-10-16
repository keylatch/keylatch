package cli

import "github.com/spf13/cobra"

// newBrokerCmd returns the top-level `broker` subcommand group.
// Exposes broker status, dry-run, and revoke subcommands.
func newBrokerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "broker",
		Short: "Install and inspect the system broker and the token broker cache",
		Long: `Install the system broker (Linux with systemd, macOS, Windows) and inspect the token broker cache.

The system broker keeps keys, secrets, policy and the audit log under its own
OS user: install, adopt, export-to-user and rotate-keys manage it, and status
reports which mode is active.

The token broker mediates credential exchanges between LLM sessions and
registered provider strategies (OAuth, AWS STS, GitHub App, etc.); its
subcommands operate on metadata only — no credential values are emitted.`,
	}
	cmd.AddCommand(newBrokerStatusCmd())
	cmd.AddCommand(newBrokerDryRunCmd())
	cmd.AddCommand(newBrokerRevokeCmd())
	cmd.AddCommand(newBrokerInstallCmd())
	cmd.AddCommand(newBrokerAdoptCmd())
	cmd.AddCommand(newBrokerExportToUserCmd())
	cmd.AddCommand(newBrokerRotateKeysCmd())
	cmd.AddCommand(newBrokerEnrollPresenceCmd())
	return cmd
}
