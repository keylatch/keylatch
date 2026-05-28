package cli

import (
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/completion"
	"github.com/spf13/cobra"
)

// newCompletionCmd returns the `completion <shell>` subcommand.
func newCompletionCmd(root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion <shell>",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script for keylatch.

Supported shells: zsh, bash, fish, pwsh

Usage:
  # Zsh
  keylatch completion zsh > ~/.zsh/_keylatch
  # Bash
  source <(keylatch completion bash)
  # Fish
  keylatch completion fish > ~/.config/fish/completions/keylatch.fish
  # PowerShell
  keylatch completion pwsh | Out-File $PROFILE -Append`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			shell := completion.Shell(args[0])
			out, err := completion.Generate(shell, root)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "completion: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprint(c.OutOrStdout(), out)
			return nil
		},
	}
	return cmd
}
