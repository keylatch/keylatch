package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// newDockerCredentialCmd is the Docker credential helper entry. The thin
// client answers it before this command runs; reaching it means the daemon
// verbs were bypassed, and the helper then reports that it has no credential.
func newDockerCredentialCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "docker-credential <get|store|erase|list>",
		Short:              "Docker credential helper that hands out placeholders, never real credentials",
		Hidden:             true,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: func(c *cobra.Command, args []string) error {
			code := control.RunDockerCredential(llmcontext.DefaultLookup, args, control.IO{In: c.InOrStdin(), Out: c.OutOrStdout(), ErrOut: c.ErrOrStderr()})
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
}
