// Package completion generates shell completion scripts for keylatch.
// Completions cover command names and flags only — connection names and
// secret values are never embedded; runtime completion is wired in separately.
package completion

import (
	"fmt"

	"github.com/spf13/cobra"
)

// RuntimeModes is the closed set of valid --runtime flag values.
// Mirrors runtime.AllModes but kept here to avoid an import cycle.
// direct_classic is the 0.1.0 non-sandboxed mode; direct_classic_sandboxed is planned for 0.2.0.
var RuntimeModes = []string{
	"gateway_typed",
	"gateway_sdk",
	"direct_brokered",
	"direct_classic",
	"direct_classic_sandboxed",
	"gateway_proxy",
}

// Shell identifies a target shell for completion generation.
type Shell string

const (
	Zsh        Shell = "zsh"
	Bash       Shell = "bash"
	Fish       Shell = "fish"
	PowerShell Shell = "pwsh"
)

// Generate returns a completion script suitable for sourcing in the given shell.
// root must be the root cobra.Command for the CLI.
func Generate(shell Shell, root *cobra.Command) (string, error) {
	switch shell {
	case Zsh:
		return generateZsh(root)
	case Bash:
		return generateBash(root)
	case Fish:
		return generateFish(root)
	case PowerShell:
		return generatePowerShell(root)
	default:
		return "", fmt.Errorf("unsupported shell %q: valid shells are zsh, bash, fish, pwsh", shell)
	}
}

// commandTree returns a depth-first ordered slice of all commands (including root).
//
//nolint:unused // planned: used for shell completion generation
func commandTree(root *cobra.Command) []*cobra.Command {
	var result []*cobra.Command
	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		result = append(result, cmd)
		for _, sub := range cmd.Commands() {
			if !sub.Hidden {
				walk(sub)
			}
		}
	}
	walk(root)
	return result
}

// subcommandNames returns the direct non-hidden subcommand Use names (first word).
func subcommandNames(cmd *cobra.Command) []string {
	var names []string
	for _, sub := range cmd.Commands() {
		if !sub.Hidden {
			names = append(names, sub.Name())
		}
	}
	return names
}
