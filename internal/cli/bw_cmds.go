package cli

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
)

// RegisterBWCommands attaches bw-related commands to root.
func RegisterBWCommands(root *cobra.Command) {
	root.AddCommand(newBWInitCmd())
	root.AddCommand(newBWListCmd())
	root.AddCommand(newBWParentCmd())
}

// newBWParentCmd returns the `bw` command group (session orchestration: H5).
func newBWParentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bw",
		Short: "Bitwarden/Vaultwarden session management (unlock, lock, status)",
	}
	cmd.AddCommand(newBWUnlockCmd())
	cmd.AddCommand(newBWLockCmd())
	cmd.AddCommand(newBWStatusCmd())
	return cmd
}

// newBWUnlockCmd returns the `bw unlock` command.
func newBWUnlockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the Bitwarden/Vaultwarden vault and cache a session token",
		Long: `bw unlock runs "bw unlock --raw" — the master password is piped to bw
via stdin, never passed as an argument or printed — and caches the
resulting session token under ~/.keylatch/sessions/ (mode 0600) for --ttl
(default 8h). Subsequent keylatch commands using the bw backend pick the
cached session up automatically (no BW_SESSION export required) via the
env-injection seam in internal/backend/bw.

Interactive terminals only: refuses to run inside an LLM-driven session and
requires a TTY on stdin. The session token itself is NEVER printed, logged,
or included in any error message.`,
	}
	cmd.Flags().Duration("ttl", bw.DefaultSessionTTL, "how long the cached session remains valid")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		env := llmcontext.DefaultLookup

		if llmcontext.IsLLMSession(env) {
			fmt.Fprintf(c.ErrOrStderr(), "Error: 'bw unlock' is interactive-only — blocked in LLM session (exit 2)\n")
			return fmt.Errorf("exit %d", exitcode.SecurityBlock)
		}
		if !stdinIsTTY() {
			fmt.Fprintf(c.ErrOrStderr(), "Error: 'bw unlock' requires an interactive terminal (no TTY on stdin)\n")
			return fmt.Errorf("exit %d", exitcode.UserError)
		}

		ttl, _ := c.Flags().GetDuration("ttl")

		cfg := loadCLIConfig(c)
		cfg.Backend = "bw"
		dispatch.ClearCached()

		b, err := dispatch.Select(ctx, cfg, env)
		if err != nil {
			if errors.Is(err, backend.ErrUnavailable) {
				fmt.Fprintf(c.ErrOrStderr(), "Error: Bitwarden CLI not available. Run: brew install bitwarden-cli\n")
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

		password, err := promptHidden("Master password")
		if err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "Error: failed to read master password: %v\n", err)
			return fmt.Errorf("exit %d", exitcode.UserError)
		}

		token, unlockErr := bwBackend.Unlock(ctx, password)
		zeroBytes(password)
		if unlockErr != nil {
			if errors.Is(unlockErr, backend.ErrLocked) {
				fmt.Fprintln(c.ErrOrStderr(), "Error: unlock failed — invalid master password")
				return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: unlock failed: %v\n", unlockErr)
			return fmt.Errorf("exit %d", exitcode.BackendUnavailable)
		}

		if err := bw.SaveSession(env, token, ttl); err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "Error: unlocked but failed to cache session: %v\n", err)
			return fmt.Errorf("exit %d", exitcode.OperationFailed)
		}

		fmt.Fprintf(c.OutOrStdout(), "Bitwarden vault unlocked; session cached (expires in %s)\n", ttl)
		return nil
	}

	return cmd
}

// newBWLockCmd returns the `bw lock` command.
func newBWLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Clear the cached Bitwarden session",
		Long: `bw lock removes the session token cached by "keylatch bw unlock".

It does NOT invoke "bw lock" against the Bitwarden CLI — the vault's actual
lock state remains managed by bw itself. This only clears keylatch's local
cache, so subsequent keylatch commands stop reusing the cached session and
fall back to requiring BW_SESSION (or a fresh "keylatch bw unlock").`,
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup
			if err := bw.ClearSession(env); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "Cached Bitwarden session cleared")
			return nil
		},
	}
}

// newBWStatusCmd returns the `bw status` command.
func newBWStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show cached Bitwarden session presence and expiry (never the token)",
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup
			st, err := bw.StatSession(env)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return err
			}
			if !st.Present {
				fmt.Fprintln(c.OutOrStdout(), "No cached Bitwarden session (run: keylatch bw unlock)")
				return nil
			}
			if st.Expired {
				fmt.Fprintf(c.OutOrStdout(), "Cached Bitwarden session EXPIRED at %s (run: keylatch bw unlock)\n",
					st.ExpiresAt.Format(time.RFC3339))
				return nil
			}
			fmt.Fprintf(c.OutOrStdout(), "Cached Bitwarden session valid until %s\n", st.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}
}

// newBWInitCmd returns the `bw-init <service>` command.
// Secret values are read via secure prompt or --from-stdin; never positional arg.
func newBWInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bw-init <service>",
		Short: "Push service credentials into Bitwarden/Vaultwarden",
		Long: `bw-init reads a secret value from a secure prompt (or --from-stdin) and
stores it in Bitwarden or a Vaultwarden self-hosted instance.

The value is NEVER read from a positional argument.
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

		// Read value from secure prompt or --from-stdin; never positional arg.
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

		// No value in output.
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
