package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newSetCmd returns the `set` subcommand for writing a credential value.
// Phase 4: accepts --expires-at, --issued-at, --owner, --scope, --max-versions.
// Security invariant S4-6: values MUST NOT be passed as positional arguments.
func newSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <path>",
		Short: "Set a credential value",
		Long: `Write a credential value at the given path.

The value is read from stdin (piped) or via an interactive prompt.
Do NOT pass secret values as command-line arguments (S4-6).

Example:
  echo 'sk-or-v1-...' | keylatch set openrouter.api_key
  keylatch set openrouter.api_key --expires-at 2026-08-01T00:00:00Z`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup

			path := args[0]

			// S4-6: check for accidental positional value argument.
			// The command requires exactly 1 arg (the path), so extra args
			// would have been caught by cobra.ExactArgs above. But if the
			// user passes the value via ENV or similar, we don't block here.

			// Parse metadata flags.
			expiresAtStr, _ := c.Flags().GetString("expires-at")
			issuedAtStr, _ := c.Flags().GetString("issued-at")
			owner, _ := c.Flags().GetString("owner")
			scope, _ := c.Flags().GetString("scope")
			maxVersions, _ := c.Flags().GetInt("max-versions")

			var partialMeta vmeta.Meta
			partialMeta.Owner = owner
			partialMeta.Scope = scope
			if maxVersions > 0 {
				partialMeta.MaxVersions = maxVersions
			}

			if expiresAtStr != "" {
				t, err := time.Parse(time.RFC3339, expiresAtStr)
				if err != nil {
					return fmt.Errorf("[keylatch] error: --expires-at must be RFC3339, e.g. 2026-08-01T00:00:00Z (exit %d)", exitcode.UserError)
				}
				partialMeta.ExpiresAt = &t
			}

			if issuedAtStr != "" {
				t, err := time.Parse(time.RFC3339, issuedAtStr)
				if err != nil {
					return fmt.Errorf("[keylatch] error: --issued-at must be RFC3339, e.g. 2026-01-01T00:00:00Z (exit %d)", exitcode.UserError)
				}
				partialMeta.IssuedAt = &t
			}

			// Read value from stdin or interactive prompt.
			var value []byte
			stdin := c.InOrStdin()

			// Check if stdin is a pipe/file (non-interactive).
			stdinFile, isFile := stdin.(*os.File)
			if isFile && !term.IsTerminal(int(stdinFile.Fd())) {
				// Piped stdin.
				var err error
				value, err = readFieldFromStdin(stdin)
				if err != nil {
					return fmt.Errorf("[keylatch] error: %w (exit %d)", err, exitcode.UserError)
				}
			} else {
				// Interactive prompt — use shared helper.
				var err error
				value, err = promptHidden(fmt.Sprintf("Enter value for %s", path))
				if err != nil {
					return fmt.Errorf("[keylatch] error: %w (exit %d)", err, exitcode.UserError)
				}
			}

			if len(value) == 0 {
				return fmt.Errorf("[keylatch] error: value must not be empty (exit %d)", exitcode.UserError)
			}

			newVersion, err := vault.RotateValue(ctx, path, value, partialMeta, cfg, env)
			if err != nil {
				return fmt.Errorf("[keylatch] error: %w (exit %d)", err, exitcode.OperationFailed)
			}

			// Canonicalize path for display.
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] set: %s — version %d\n", path, newVersion)
			return nil
		},
	}

	cmd.Flags().String("expires-at", "", "RFC3339 expiry timestamp (e.g. 2026-08-01T00:00:00Z)")
	cmd.Flags().String("issued-at", "", "RFC3339 issue timestamp")
	cmd.Flags().String("owner", "", "owner of the credential")
	cmd.Flags().String("scope", "", "scope (e.g. 'production')")
	cmd.Flags().Int("max-versions", 0, "maximum versions to retain (0 = backend default)")

	return cmd
}
