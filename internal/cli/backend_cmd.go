package cli

import "github.com/spf13/cobra"

// newBackendCmd returns the `keylatch backend` subcommand group.
func newBackendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backend",
		Short: "List secret backends and manage root-of-trust adapters",
	}
	cmd.AddCommand(newBackendListCmd())
	registerBackendVault(cmd)
	cmd.AddCommand(newBackendUpgradeTrustCmd())
	cmd.AddCommand(newBackendLoginCmd())
	return cmd
}
