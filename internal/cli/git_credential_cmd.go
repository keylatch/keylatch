package cli

import "github.com/spf13/cobra"

// newGitCredentialCmd is the target of the git credential helper entry the
// daemon places in a placeholder session's environment. The thin client
// answers it through the daemon before this command runs; reaching it means no
// daemon was available, and an empty answer tells git there is no credential.
func newGitCredentialCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "git-credential <get|store|erase>",
		Short:              "Git credential helper that hands out placeholders, never real credentials",
		Hidden:             true,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE:               func(*cobra.Command, []string) error { return nil },
	}
}
