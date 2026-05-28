package cli

import "github.com/spf13/cobra"

// newTokenCmd returns the `token` command group.
func newTokenCmd() *cobra.Command {
	token := &cobra.Command{
		Use:   "token",
		Short: "Manage session tokens and the token broker",
	}
	token.AddCommand(newTokenBrokerCmd())
	return token
}

// newTokenBrokerCmd returns the `token broker` subcommand group.
// P0.4: broker subcommands are stubs — hide the whole group from help.
func newTokenBrokerCmd() *cobra.Command {
	broker := &cobra.Command{
		Use:    "broker",
		Short:  "Token broker management commands",
		Hidden: true,
	}
	broker.AddCommand(newBrokerStatusCmd())
	broker.AddCommand(newBrokerDryRunCmd())
	broker.AddCommand(newBrokerRevokeCmd())
	return broker
}
