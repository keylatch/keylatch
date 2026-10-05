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
// Security invariant: blocked in LLM sessions.
func newRollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback <path> <version>",
		Short: "Roll back a credential to an older version",
		Long: `Create a new version with the same plaintext as an older version.

Version numbers are monotonically increasing — rollback creates a new version
rather than moving a pointer. The new version's metadata records which version
was rolled back from.

Blocked in LLM sessions. Requires confirmation or --force.`,
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup

			// Block in LLM sessions.
			if llmcontext.IsLLMSession(env) {
				return NewSecurityBlock("rollback requires a human terminal. Run outside an LLM session.")
			}

			path := args[0]
			versionStr := args[1]
			version, err := strconv.Atoi(versionStr)
			if err != nil {
				return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: version must be an integer, got %q", versionStr))
			}

			force, _ := c.Flags().GetBool("force")

			fmt.Fprintf(c.ErrOrStderr(),
				"Rolling back %s to version %d — a new version will be created.\n", path, version)

			if !force {
				if !confirmPrompt(c, "Proceed? [y/N]: ") {
					return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] aborted"))
				}
			}

			if err := vault.Rollback(ctx, path, version, cfg, env); err != nil {
				switch {
				case errors.Is(err, vault.ErrVersionDestroyed):
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: version %d is destroyed and cannot be rolled back", version))
				case errors.Is(err, vault.ErrVersionDeleted):
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: version %d is deleted and cannot be rolled back", version))
				case errors.Is(err, vault.ErrVersionNotFound):
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: version %d not found", version))
				default:
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: %w", err))
				}
			}

			// Get new current version for the output message.
			m, err := vault.GetMeta(ctx, path, cfg, env)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: GetMeta after rollback: %w", err))
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
