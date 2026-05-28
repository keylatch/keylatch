package cli

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/spf13/cobra"
)

// newRollbackCmd returns the `rollback` subcommand.
// Security invariant S4-8: blocked in LLM sessions.
func newRollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback <path> <version>",
		Short: "Roll back a credential to an older version",
		Long: `Create a new version with the same plaintext as an older version.

Version numbers are monotonically increasing — rollback creates a new version
rather than moving a pointer. The new version's metadata records which version
was rolled back from.

Blocked in LLM sessions (S4-8). Requires confirmation or --force.`,
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup

			// S4-8: block in LLM sessions.
			if llmcontext.IsLLMSession(env) {
				return fmt.Errorf("[keylatch] security block: rollback requires a human terminal. Run outside an LLM session. (exit %d)", exitcode.SecurityBlock)
			}

			path := args[0]
			versionStr := args[1]
			version, err := strconv.Atoi(versionStr)
			if err != nil {
				return fmt.Errorf("[keylatch] error: version must be an integer, got %q (exit %d)", versionStr, exitcode.UserError)
			}

			force, _ := c.Flags().GetBool("force")

			fmt.Fprintf(c.ErrOrStderr(),
				"Rolling back %s to version %d — a new version will be created.\n", path, version)

			if !force {
				if !confirmPrompt(c, "Proceed? [y/N]: ") {
					return fmt.Errorf("[keylatch] aborted (exit %d)", exitcode.UserError)
				}
			}

			if err := vault.Rollback(ctx, path, version, cfg, env); err != nil {
				switch {
				case errors.Is(err, vault.ErrVersionDestroyed):
					return fmt.Errorf("[keylatch] error: version %d is destroyed and cannot be rolled back (exit %d)", version, exitcode.OperationFailed)
				case errors.Is(err, vault.ErrVersionDeleted):
					return fmt.Errorf("[keylatch] error: version %d is deleted and cannot be rolled back (exit %d)", version, exitcode.OperationFailed)
				case errors.Is(err, vault.ErrVersionNotFound):
					return fmt.Errorf("[keylatch] error: version %d not found (exit %d)", version, exitcode.OperationFailed)
				default:
					return fmt.Errorf("[keylatch] error: %w (exit %d)", err, exitcode.OperationFailed)
				}
			}

			// Get new current version for the output message.
			m, err := vault.GetMeta(ctx, path, cfg, env)
			if err != nil {
				return fmt.Errorf("[keylatch] error: GetMeta after rollback: %w (exit %d)", err, exitcode.OperationFailed)
			}

			fmt.Fprintf(c.OutOrStdout(),
				"[keylatch] rollback: %s version %d → new version %d (rolled back from %d)\n",
				path, version, m.CurrentVersion, version)
			return nil
		},
	}

	cmd.Flags().Bool("force", false, "skip confirmation prompt")
	return cmd
}
