package cli

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/backend/op"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
)

// RegisterOPCommands attaches op-related commands to root.
func RegisterOPCommands(root *cobra.Command) {
	root.AddCommand(newOPInitCmd())
	root.AddCommand(newOPListCmd())
}

// newOPInitCmd returns the `op-init <service>` command.
// Secret values are read via secure prompt or --from-stdin; never positional arg.
func newOPInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "op-init <service>",
		Short: "Push service credentials into a 1Password vault",
		Long: `op-init reads a secret value from a secure prompt (or --from-stdin) and
stores it in the configured 1Password vault using the op CLI.

The value is NEVER read from a positional argument.`,
		Args: cobra.ExactArgs(1),
	}

	cmd.Flags().String("field", "api_key", "field name to set in the 1Password item")
	cmd.Flags().Bool("from-stdin", false, "read the secret value from stdin instead of interactive prompt")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		service := args[0]
		field, _ := c.Flags().GetString("field")
		fromStdin, _ := c.Flags().GetBool("from-stdin")

		cfg := loadCLIConfig(c)
		cfg.Backend = "op"
		dispatch.ClearCached()
		env := llmcontext.DefaultLookup

		b, err := dispatch.Select(ctx, cfg, env)
		if err != nil {
			if errors.Is(err, backend.ErrUnavailable) {
				fmt.Fprintf(c.ErrOrStderr(),
					"Error: 1Password CLI not available. Run: brew install 1password-cli\n")
				return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return err
		}

		opBackend, ok := b.(*op.OnePasswordBackend)
		if !ok {
			fmt.Fprintf(c.ErrOrStderr(), "Error: backend is not a OnePasswordBackend\n")
			return fmt.Errorf("exit %d", exitcode.UserError)
		}

		// Read value from secure prompt or --from-stdin; never positional arg.
		var value []byte
		if fromStdin {
			scanner := bufio.NewScanner(c.InOrStdin())
			if scanner.Scan() {
				value = []byte(strings.TrimRight(scanner.Text(), "\n"))
			}
		} else {
			// Interactive masked prompt.
			fmt.Fprintf(c.OutOrStdout(), "Enter secret value for %s.%s: ", service, field)
			value, err = readPasswordFromTerminal(c.OutOrStdout())
			fmt.Fprintln(c.OutOrStdout()) // newline after masked input
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: failed to read secret: %v\n", err)
				return fmt.Errorf("exit %d", exitcode.UserError)
			}
		}

		canonical := "default/" + service + "/" + field
		if err := opBackend.Set(ctx, canonical, value, backend.Meta{}); err != nil {
			if errors.Is(err, backend.ErrLocked) {
				fmt.Fprintf(c.ErrOrStderr(), "Error: 1Password vault locked. Run: eval $(op signin)\n")
				return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return err
		}

		// No value in output.
		vaultName := "Keylatch"
		if cfg.OP != nil && cfg.OP.Vault != "" {
			vaultName = cfg.OP.Vault
		}
		fmt.Fprintf(c.OutOrStdout(), "Pushed %s to 1Password vault %s\n", service, vaultName)
		return nil
	}

	return cmd
}

// newOPListCmd returns the `op-list` command.
func newOPListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "op-list",
		Short: "List Keylatch-managed items in the 1Password vault",
		Long:  `op-list lists all items managed by Keylatch in the configured 1Password vault. No field values or accessor UUIDs are printed.`,
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()

			cfg := loadCLIConfig(c)
			cfg.Backend = "op"
			dispatch.ClearCached()
			env := llmcontext.DefaultLookup

			b, err := dispatch.Select(ctx, cfg, env)
			if err != nil {
				if errors.Is(err, backend.ErrUnavailable) {
					fmt.Fprintf(c.ErrOrStderr(),
						"Error: 1Password CLI not available. Run: brew install 1password-cli\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			entries, err := b.List(ctx, "")
			if err != nil {
				if errors.Is(err, backend.ErrUnavailable) {
					fmt.Fprintf(c.ErrOrStderr(), "Run: brew install 1password-cli\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				if errors.Is(err, backend.ErrLocked) {
					fmt.Fprintf(c.ErrOrStderr(), "Error: Run: eval $(op signin)\n")
					return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}

			vaultName := "Keylatch"
			if cfg.OP != nil && cfg.OP.Vault != "" {
				vaultName = cfg.OP.Vault
			}

			if len(entries) == 0 {
				fmt.Fprintf(c.OutOrStdout(),
					"No Keylatch-managed items found in vault %s\n", vaultName)
				return nil
			}

			// Table header: connection | last_updated (no values, no UUIDs).
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

// readPasswordFromTerminal reads a masked password from the terminal.
// Falls back to bufio if the terminal is not available (e.g. in tests).
func readPasswordFromTerminal(w io.Writer) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		return term.ReadPassword(fd)
	}
	// Non-interactive fallback (tests, pipes).
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return []byte(strings.TrimRight(scanner.Text(), "\n")), nil
	}
	return nil, scanner.Err()
}

// ensure op package is used.
var _ *op.OnePasswordBackend
