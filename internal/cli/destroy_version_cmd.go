package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newDestroyVersionCmd returns the `destroy-version` subcommand.
// Security invariant: blocked in LLM sessions.
func newDestroyVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "destroy-version <path> <version>",
		Short: "Permanently destroy a credential version",
		Long: `Permanently destroy a specific version of a credential.

This action is irreversible. The ciphertext is deleted and the metadata is
marked as destroyed — even if the physical file persists, GetVersion will be
blocked at the metadata layer.

Blocked in LLM sessions. Requires confirmation or --force.`,
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := c.Context()
			cfg := loadCLIConfig(c)
			env := llmcontext.DefaultLookup

			// Block in LLM sessions.
			if llmcontext.IsLLMSession(env) {
				return fmt.Errorf("[keylatch] security block: destroy-version requires a human terminal. Run outside an LLM session. (exit %d)", exitcode.SecurityBlock)
			}

			path := args[0]
			versionStr := args[1]
			version, err := strconv.Atoi(versionStr)
			if err != nil {
				return fmt.Errorf("[keylatch] error: version must be an integer, got %q (exit %d)", versionStr, exitcode.UserError)
			}

			force, _ := c.Flags().GetBool("force")

			// Require confirmation unless --force.
			if !force {
				if !confirmPrompt(c,
					fmt.Sprintf("Destroy version %d of %s? This is irreversible. [y/N]: ", version, path)) {
					return fmt.Errorf("[keylatch] aborted (exit %d)", exitcode.UserError)
				}
			}

			if err := vault.DestroyVersion(ctx, path, version, cfg, env); err != nil {
				switch {
				case errors.Is(err, vault.ErrVersionDestroyed):
					return fmt.Errorf("[keylatch] error: version %d is already destroyed (exit %d)", version, exitcode.OperationFailed)
				case errors.Is(err, vault.ErrDestroyCurrentVersion):
					return fmt.Errorf("[keylatch] error: cannot destroy the current version — rotate first (exit %d)", exitcode.OperationFailed)
				default:
					return fmt.Errorf("[keylatch] error: %w (exit %d)", err, exitcode.OperationFailed)
				}
			}

			fmt.Fprintf(c.OutOrStdout(), "[keylatch] destroyed: %s version %d\n", path, version)
			return nil
		},
	}

	cmd.Flags().Bool("force", false, "skip confirmation prompt")
	return cmd
}

// confirmPrompt prints prompt and reads a line from stdin. Returns true only
// for "y" or "yes" (case-insensitive). In non-interactive mode (stdin is not a
// TTY), returns false unless --force is used.
func confirmPrompt(c *cobra.Command, prompt string) bool {
	stdin := c.InOrStdin()
	stdinFile, isFile := stdin.(*os.File)
	if isFile && !term.IsTerminal(int(stdinFile.Fd())) {
		// Non-interactive — confirmation not possible.
		return false
	}

	fmt.Fprint(c.ErrOrStderr(), prompt)
	scanner := bufio.NewScanner(stdin)
	if !scanner.Scan() {
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes"
}
