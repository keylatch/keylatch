package cli

import (
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
)

// newDisconnectCmd returns the `disconnect` subcommand.
// Removes a stored connection (all secret fields, config fields, and metadata)
// for the given provider. Equivalent to calling `keylatch destroy-version`
// on each stored path but operates at the provider level.
func newDisconnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disconnect <provider>",
		Short: "Remove a stored credential connection",
		Long: `Remove a stored credential connection and all associated data.

This deletes the secret fields, config fields, and connection metadata for the
given provider. The action is irreversible. Use 'keylatch list' to see current
connections.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			st := newDispatchedStore(cfg, llmcontext.DefaultLookup)

			provider := args[0]
			namespace, _ := c.Flags().GetString("namespace")
			account, _ := c.Flags().GetString("account")
			if namespace == "" {
				namespace = "default"
			}
			if account == "" {
				account = "default"
			}

			if err := connections.Delete(ctx, provider, account, namespace, st); err != nil {
				if err == connections.ErrProviderNotFound {
					fmt.Fprintf(c.ErrOrStderr(), "Error: provider %q not found in registry.\n", provider)
					os.Exit(exitcode.UserError)
					return nil
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "v %s — disconnected\n", provider)
			return nil
		},
	}
	cmd.Flags().String("namespace", "default", "vault namespace")
	cmd.Flags().String("account", "default", "account name (multi-account providers)")
	return cmd
}
