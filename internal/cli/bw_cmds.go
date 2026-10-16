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
	"github.com/keylatch/keylatch/internal/config"
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

// newBWParentCmd returns the `bw` command group (session orchestration).
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
via stdin, never passed as an argument or printed — and keeps the resulting
session token for --ttl (default bw.session_ttl, else 1h; at most 8h). The
token is stored only wrapped by the vault key, never in plaintext, and the
bw backend picks it up automatically (no BW_SESSION export required).
"keylatch bw lock" deletes it.

Interactive terminals only: refuses to run inside an LLM-driven session and
requires a TTY on stdin. The session token itself is NEVER printed, logged,
or included in any error message.`,
	}
	cmd.Flags().Duration("ttl", 0, "how long the session remains valid (default: bw.session_ttl, else 1h; at most 8h)")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		ctx := c.Context()
		env := llmcontext.DefaultLookup

		if llmcontext.IsLLMSession(env) {
			fmt.Fprintf(c.ErrOrStderr(), "Error: 'bw unlock' is interactive-only — blocked in LLM session (exit 2)\n")
			return reported(exitcode.SecurityBlock, nil)
		}
		if !stdinIsTTY() {
			fmt.Fprintf(c.ErrOrStderr(), "Error: 'bw unlock' requires an interactive terminal (no TTY on stdin)\n")
			return reported(exitcode.UserError, nil)
		}

		cfg := loadCLIConfig(c)
		ttl, _ := c.Flags().GetDuration("ttl")
		if ttl <= 0 {
			ttl = configuredBWSessionTTL(cfg)
		}
		if ttl > bw.MaxSessionTTL {
			fmt.Fprintf(c.ErrOrStderr(), "Error: a session may last at most %s\n", bw.MaxSessionTTL)
			return reported(exitcode.UserError, bw.ErrSessionTTLTooLong)
		}
		cfg.Backend = "bw"
		dispatch.ClearCached()

		b, err := dispatch.Select(ctx, cfg, env)
		if err != nil {
			if errors.Is(err, backend.ErrUnavailable) {
				fmt.Fprintf(c.ErrOrStderr(), "Error: Bitwarden CLI not available. Run: brew install bitwarden-cli\n")
				return reported(exitcode.BackendUnavailable, nil)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return reported(exitcode.UserError, err)
		}

		bwBackend, ok := b.(*bw.BitwardenBackend)
		if !ok {
			fmt.Fprintf(c.ErrOrStderr(), "Error: backend is not a BitwardenBackend\n")
			return reported(exitcode.UserError, nil)
		}

		password, err := promptHidden("Master password")
		if err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "Error: failed to read master password: %v\n", err)
			return reported(exitcode.UserError, nil)
		}

		token, unlockErr := bwBackend.Unlock(ctx, password)
		zeroBytes(password)
		if unlockErr != nil {
			if errors.Is(unlockErr, backend.ErrLocked) {
				fmt.Fprintln(c.ErrOrStderr(), "Error: unlock failed — invalid master password")
				return reported(exitcode.BackendUnavailable, nil)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: unlock failed: %v\n", unlockErr)
			return reported(exitcode.BackendUnavailable, nil)
		}

		if err := saveBWSession(env, token, ttl); err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "Error: unlocked but failed to keep the session: %v\n", err)
			return reported(exitcode.OperationFailed, nil)
		}

		fmt.Fprintf(c.OutOrStdout(), "Bitwarden vault unlocked; session kept sealed (expires in %s)\n", ttl)
		return nil
	}

	return cmd
}

// configuredBWSessionTTL is bw.session_ttl, or the default when it is unset or
// unreadable (config validation rejects a bad value).
func configuredBWSessionTTL(cfg config.Config) time.Duration {
	if cfg.BW != nil && cfg.BW.SessionTTL != "" {
		if d, err := time.ParseDuration(cfg.BW.SessionTTL); err == nil && d > 0 {
			return d
		}
	}
	return bw.DefaultSessionTTL
}

// bwSessionKEK opens the vault key the session is sealed under; tests replace it.
var bwSessionKEK = bw.DefaultKEK

// saveBWSession seals the session token under the vault key.
func saveBWSession(env llmcontext.Lookup, token string, ttl time.Duration) error {
	k, err := bwSessionKEK(env)
	if err != nil {
		return fmt.Errorf("open the vault key: %w", err)
	}
	return bw.SaveSession(env, k, token, ttl)
}

// newBWLockCmd returns the `bw lock` command.
func newBWLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Clear the cached Bitwarden session",
		Long: `bw lock removes the session token kept by "keylatch bw unlock", and
any plaintext session file an earlier version left under sessions/.

It does NOT invoke "bw lock" against the Bitwarden CLI — the vault's actual
lock state remains managed by bw itself. This only clears keylatch's local
cache, so subsequent keylatch commands stop reusing the cached session and
fall back to requiring BW_SESSION (or a fresh "keylatch bw unlock").`,
		RunE: func(c *cobra.Command, args []string) error {
			env := llmcontext.DefaultLookup
			if err := bw.ClearSession(env); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return reported(exitcode.UserError, err)
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
				return reported(exitcode.UserError, err)
			}
			if st.LegacyPlaintext {
				fmt.Fprintln(c.ErrOrStderr(), "Warning: a plaintext Bitwarden session file is on disk; run: keylatch bw lock")
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
				return reported(exitcode.BackendUnavailable, nil)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return reported(exitcode.UserError, err)
		}

		bwBackend, ok := b.(*bw.BitwardenBackend)
		if !ok {
			fmt.Fprintf(c.ErrOrStderr(), "Error: backend is not a BitwardenBackend\n")
			return reported(exitcode.UserError, nil)
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
				return reported(exitcode.UserError, nil)
			}
		}

		canonical := "default/" + service + "/" + field
		if err := bwBackend.Set(ctx, canonical, value, backend.Meta{}); err != nil {
			if errors.Is(err, backend.ErrLocked) {
				fmt.Fprintf(c.ErrOrStderr(),
					"Error: Vault is locked — set BW_SESSION (see README §Non-interactive use)\n")
				return reported(exitcode.BackendUnavailable, nil)
			}
			fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
			return reported(exitcode.UserError, err)
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
					fmt.Fprintf(c.ErrOrStderr(), "Error: Bitwarden CLI not available. Run: brew install bitwarden-cli\n")
					return reported(exitcode.BackendUnavailable, nil)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return reported(exitcode.UserError, err)
			}

			entries, err := b.List(ctx, "")
			if err != nil {
				if errors.Is(err, backend.ErrUnavailable) {
					fmt.Fprintf(c.ErrOrStderr(), "Error: Bitwarden CLI not available. Run: brew install bitwarden-cli\n")
					return reported(exitcode.BackendUnavailable, nil)
				}
				if errors.Is(err, backend.ErrLocked) {
					fmt.Fprintf(c.ErrOrStderr(),
						"Error: Vault is locked — set BW_SESSION (see README §Non-interactive use)\n")
					return reported(exitcode.BackendUnavailable, nil)
				}
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				return reported(exitcode.UserError, err)
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
