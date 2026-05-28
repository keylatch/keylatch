package cli

import (
	"bufio"
	"errors"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
)

// RegisterBWCommands attaches Phase 2 bw-related commands to root.
func RegisterBWCommands(root *cobra.Command) {
	root.AddCommand(newBWInitCmd())
	root.AddCommand(newBWListCmd())
}

// newBWInitCmd returns the `bw-init <service>` command.
// S2-6: secret values are read via secure prompt or --from-stdin; never positional arg.
func newBWInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bw-init <service>",
		Short: "Push service credentials into Bitwarden/Vaultwarden",
		Long: `bw-init reads a secret value from a secure prompt (or --from-stdin) and
stores it in Bitwarden or a Vaultwarden self-hosted instance.

The value is NEVER read from a positional argument (S2-6).
BW_SESSION must be set in the environment before running bw-init.`,
		Args: cobra.ExactArgs(1),
	}

	cmd.Flags().String("field", "api_key", "field name to set in the Bitwarden item")
	cmd.Flags().Bool("from-stdin", false, "read the secret value from stdin instead of interactive prompt")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		service := args[0]
		field, _ := c.Flags().GetString("field")
		fromStdin, _ := c.Flags().GetBool("from-stdin")

		cfg := loadCLIConfig(c)
		cfg.Backend = "bw"
		dispatch.ClearCached()
		env := llmcontext.DefaultLookup

		b, err := dispatch.Select(ctx, cfg, env)
		if err != nil {
			if errors.Is(err, backend.ErrUnavailable) {
				fmt.Fprintf(c.ErrOrStderr(),
					"Error: Bitwarden CLI not available. Run: brew install bitwarden-cli\n")
				return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return err
		}

		bwBackend, ok := b.(*bw.BitwardenBackend)
		if !ok {
			fmt.Fprintf(c.ErrOrStderr(), "Error: backend is not a BitwardenBackend\n")
			return fmt.Errorf("exit %d", exitcode.UserError)
		}

		// S2-6: read value from secure prompt or --from-stdin; never positional arg.
		var value []byte
		if fromStdin {
			scanner := bufio.NewScanner(c.InOrStdin())
			if scanner.Scan() {
				value = []byte(strings.TrimRight(scanner.Text(), "\n"))
			}
		} else {
			fmt.Fprintf(c.OutOrStdout(), "Enter secret value for %s.%s: ", service, field)
			var readErr error
			value, readErr = readPasswordFromTerminal(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout())
			if readErr != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: failed to read secret: %v\n", readErr)
				return fmt.Errorf("exit %d", exitcode.UserError)
			}
		}

		canonical := "default/" + service + "/" + field
		if err := bwBackend.Set(ctx, canonical, value, backend.Meta{}); err != nil {
			if errors.Is(err, backend.ErrLocked) {
				fmt.Fprintf(c.ErrOrStderr(),
					"Error: Vault is locked — set BW_SESSION (see README §Non-interactive use)\n")
				return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return err
		}

		// S2-1: no value in output.
		fmt.Fprintf(c.OutOrStdout(), "Pushed %s to Bitwarden\n", service)
		return nil
	}

	return cmd
}

// newBWListCmd returns the `bw-list` command.
func newBWListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bw-list",
		Short: "List Keylatch-managed items in Bitwarden/Vaultwarden",
		Long:  `bw-list lists all items managed by Keylatch in Bitwarden or Vaultwarden. No field values are printed. BW_SESSION must not appear in output.`,
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()

			cfg := loadCLIConfig(c)
			cfg.Backend = "bw"
			dispatch.ClearCached()
			env := llmcontext.DefaultLookup

			b, err := dispatch.Select(ctx, cfg, env)
			if err != nil {
				if errors.Is(err, backend.ErrUnavailable) {
					fmt.Fprintf(c.ErrOrStderr(), "Run: brew install bitwarden-cli\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			entries, err := b.List(ctx, "")
			if err != nil {
				if errors.Is(err, backend.ErrUnavailable) {
					fmt.Fprintf(c.ErrOrStderr(), "Run: brew install bitwarden-cli\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				if errors.Is(err, backend.ErrLocked) {
					fmt.Fprintf(c.ErrOrStderr(),
						"Vault is locked — set BW_SESSION (see README §Non-interactive use)\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			if len(entries) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "No Keylatch-managed items found in Bitwarden")
				return nil
			}

			// Table: connection/field | last_updated. No values, no session token.
			fmt.Fprintf(c.OutOrStdout(), "%-30s  %-30s\n", "CONNECTION/FIELD", "LAST_UPDATED")
			fmt.Fprintf(c.OutOrStdout(), "%s  %s\n",
				strings.Repeat("-", 30), strings.Repeat("-", 30))
			for _, e := range entries {
				updated := ""
				if !e.UpdatedAt.IsZero() {
					updated = e.UpdatedAt.Format("2006-01-02T15:04:05Z")
				}
				fmt.Fprintf(c.OutOrStdout(), "%-30s  %-30s\n", e.Path, updated)
			}
			return nil
		},
	}
}

// ensure bw package is used.
var _ *bw.BitwardenBackend
