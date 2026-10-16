package cli

// install_guard_cmd.go implements `keylatch install-guard`, the older spelling
// of `keylatch agent install`.

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/harness"
)

const installGuardDeprecation = "keylatch install-guard is deprecated and will be removed in a later release; use keylatch agent install (and keylatch agent uninstall)."

// newInstallGuardCmd returns the `keylatch install-guard` command. It does what
// `agent install` does and prints a deprecation notice on standard error.
func newInstallGuardCmd() *cobra.Command {
	var f installFlags
	var list, uninstall bool

	cmd := &cobra.Command{
		Use:   "install-guard <agent>",
		Short: "Install an agent exfiltration guard (deprecated: use agent install)",
		Long: `Deprecated alias of 'keylatch agent install'. It installs the pre-tool hook,
the MCP server and the rules block into the agent's own configuration by
structured merge, keeping every other setting, hook and comment. The previous
file is saved as <name>.keylatch.bak; --upgrade refreshes an installed entry,
--dry-run prints a diff, --all installs every agent found on this machine.

` + harnessTable() + `
The guard is 'keylatch guard hook --harness <id>': it parses each shell command
and checks each file tool's paths, and denies on a credential read, a
secret-manager call or an environment dump (exit 2 plus the harness's deny
JSON). Keylatch's own LLM-session guard (Layer 1) still applies even without
the hook; the hook is a second layer at the agent framework level.

Aider has no hook API; start it with 'keylatch launch -- aider'.

Use --list to show all supported agents with their hook mechanism type.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if list {
				return runInstallGuardList(cmd)
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Warning: "+installGuardDeprecation)
			if len(args) > 0 {
				if d, ok := harness.Resolve(args[0]); ok && d.Support == harness.SupportLaunchOnly {
					return fmt.Errorf("install-guard: %s has no hook API; start it with 'keylatch launch -- %s'", d.Name, d.Executables[0])
				}
			}
			if uninstall {
				return runHarnessUninstall(cmd, args, f)
			}
			return runHarnessInstall(cmd, args, f)
		},
	}

	addInstallFlags(cmd, &f)
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove what was installed (needs a human at a terminal)")
	cmd.Flags().BoolVar(&list, "list", false, "list all supported agents with their hook mechanism type")
	cmd.Flags().BoolVar(&f.parts.Guard, "guard", false, "only the pre-tool hook")
	cmd.Flags().BoolVar(&f.parts.MCP, "mcp", false, "only the MCP server")
	cmd.Flags().BoolVar(&f.parts.Rules, "rules", false, "only the rules block")
	return cmd
}

func runInstallGuardList(cmd *cobra.Command) error {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Supported agents for keylatch agent install:")
	fmt.Fprintln(w)
	for _, d := range harness.All() {
		switch d.Support {
		case harness.SupportGuard:
			fmt.Fprintf(w, "  %-15s  %s (%s)\n", d.ID, strings.Join(d.Hook.Events, ", "), d.HookDisplay())
		case harness.SupportLaunchOnly:
			fmt.Fprintf(w, "  %-15s  launch only (keylatch launch -- %s)\n", d.ID, d.Executables[0])
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Example: keylatch agent install claude-code")
	return nil
}
