package cli

import (
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/harness/installer"
	"github.com/keylatch/keylatch/internal/presence"
)

// installFlags are the options every harness install shares.
type installFlags struct {
	project, dryRun, upgrade, all bool
	configDirs                    []string
	parts                         installer.Parts
}

func (f installFlags) opts() guard.InstallOpts {
	o := guard.InstallOpts{Upgrade: f.upgrade, DryRun: f.dryRun, ConfigDirs: f.configDirs}
	if f.project {
		o.ProjectDir = "."
	}
	return o
}

func addInstallFlags(cmd *cobra.Command, f *installFlags) {
	cmd.Flags().BoolVar(&f.project, "project", false, "write the current project's files instead of the user's")
	cmd.Flags().BoolVar(&f.upgrade, "upgrade", false, "refresh installed entries in place: new binary path, matcher and timeout")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "print a unified diff of every change and write nothing")
	cmd.Flags().StringSliceVar(&f.configDirs, "config-dir", nil, "also install into this Claude Code configuration directory; repeatable (claude-code only)")
	cmd.Flags().BoolVar(&f.all, "all", false, "every harness found on this machine")
}

func newAgentInstallCmd() *cobra.Command {
	var f installFlags
	cmd := &cobra.Command{
		Use:   "install <harness> [--guard] [--mcp] [--rules]",
		Short: "Install the Keylatch guard, MCP server and rules into an agent harness",
		Long: `Install writes, by structured merge that keeps every other key, hook and
comment, up to three things into a harness's own configuration:

  --guard   a pre-tool hook that runs 'keylatch guard hook --harness <id>', which
            denies credential reads, secret-manager calls and environment dumps
  --mcp     the Keylatch MCP server ('keylatch mcp --stdio')
  --rules   a block in the harness's rules file telling the agent to use
            'keylatch run' and never to ask for keys

With none of the three named, all of them are installed. Every file is saved as
<name>.keylatch.bak before it changes; --dry-run prints the diff instead.

` + harnessTable() + `
Aider and Goose have no hook mechanism: 'keylatch agent install aider' prints
how to start them with 'keylatch launch' and changes no file.

Example:
  keylatch agent install claude-code --dry-run
  keylatch agent install --all`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runHarnessInstall(c, args, f)
		},
	}
	addInstallFlags(cmd, &f)
	cmd.Flags().BoolVar(&f.parts.Guard, "guard", false, "install the pre-tool hook")
	cmd.Flags().BoolVar(&f.parts.MCP, "mcp", false, "register the MCP server")
	cmd.Flags().BoolVar(&f.parts.Rules, "rules", false, "write the rules block")
	return cmd
}

func newAgentUninstallCmd() *cobra.Command {
	var f installFlags
	cmd := &cobra.Command{
		Use:   "uninstall <harness> [--guard] [--mcp] [--rules]",
		Short: "Remove what agent install wrote (needs a human at a terminal)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runHarnessUninstall(c, args, f)
		},
	}
	cmd.Flags().BoolVar(&f.project, "project", false, "remove the current project's files instead of the user's")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "print the diff and write nothing")
	cmd.Flags().BoolVar(&f.all, "all", false, "every harness found on this machine")
	cmd.Flags().BoolVar(&f.parts.Guard, "guard", false, "remove the pre-tool hook")
	cmd.Flags().BoolVar(&f.parts.MCP, "mcp", false, "remove the MCP server")
	cmd.Flags().BoolVar(&f.parts.Rules, "rules", false, "remove the rules block")
	return cmd
}

// harnessTable lists the supported harnesses and what each gets.
func harnessTable() string {
	var b strings.Builder
	b.WriteString("Harnesses:\n")
	for _, d := range harness.All() {
		switch d.Support {
		case harness.SupportGuard:
			fmt.Fprintf(&b, "  %-12s %s hook in %s\n", d.ID, strings.Join(d.Hook.Events, ", "), d.HookDisplay())
		case harness.SupportLaunchOnly:
			fmt.Fprintf(&b, "  %-12s launch only: keylatch launch -- %s\n", d.ID, d.Executables[0])
		}
	}
	return b.String()
}

// harnessTargets resolves the harnesses a command acts on: the named one, or with
// --all every installable harness that is present on this machine.
func harnessTargets(args []string, all bool) ([]harness.Descriptor, error) {
	if all {
		if len(args) > 0 {
			return nil, NewUsageError("name a harness or use --all, not both")
		}
		env, err := harness.SystemEnv()
		if err != nil {
			return nil, NewInternalError("cannot determine the home directory: %v", err)
		}
		var out []harness.Descriptor
		for _, d := range harness.Installable() {
			if harnessPresent(d, env) {
				out = append(out, d)
			}
		}
		if len(out) == 0 {
			return nil, NewUsageError("no supported agent harness was found on this machine; name one explicitly")
		}
		return out, nil
	}
	if len(args) == 0 {
		return nil, NewUsageError("name a harness (one of %s) or use --all", strings.Join(installableIDs(), ", "))
	}
	d, ok := harness.Resolve(args[0])
	if !ok {
		return nil, NewUsageError("unknown harness %q\n\nSupported: %s\nExample: keylatch agent install claude-code", args[0], strings.Join(installableIDs(), ", "))
	}
	return []harness.Descriptor{d}, nil
}

func installableIDs() []string {
	var ids []string
	for _, d := range harness.Installable() {
		ids = append(ids, d.ID)
	}
	return ids
}

// harnessPresent reports whether the harness's configuration directory exists
// or one of its executables is on PATH.
func harnessPresent(d harness.Descriptor, env harness.Env) bool {
	if installer.Inspect(d, env).Detected {
		return true
	}
	return slices.ContainsFunc(d.Executables, func(exe string) bool {
		_, err := exec.LookPath(exe)
		return err == nil
	})
}

func launchOnlyUsage(w io.Writer, d harness.Descriptor) {
	exe := d.Executables[0]
	fmt.Fprintf(w, "%s has no hook mechanism, so Keylatch edits none of its files.\n", d.Name)
	fmt.Fprintf(w, "Start it through Keylatch instead:\n\n  keylatch launch -- %s\n\n", exe)
	fmt.Fprintln(w, "The session runs as a registered agent: Keylatch serves it placeholders and gateway")
	fmt.Fprintln(w, "credentials, never the stored values.")
}

func runHarnessInstall(cmd *cobra.Command, args []string, f installFlags) error {
	ds, err := harnessTargets(args, f.all)
	if err != nil {
		return err
	}
	if len(f.configDirs) > 0 && (len(ds) != 1 || ds[0].ID != string(guard.AgentClaudeCode)) {
		return NewUsageError("--config-dir applies to claude-code only")
	}
	w := cmd.OutOrStdout()
	for _, d := range ds {
		if d.Support == harness.SupportLaunchOnly {
			launchOnlyUsage(w, d)
			continue
		}
		res, err := guard.InstallHarness(d, installer.Options{Parts: f.parts}, f.opts())
		if err != nil {
			return fmt.Errorf("agent install: %s: %w", d.ID, err)
		}
		if len(ds) > 1 {
			fmt.Fprintf(w, "== %s\n", d.Name)
		}
		printInstall(w, res, f.dryRun)
		if d.ID == "cursor" && f.parts.Resolve().Guard && !f.dryRun {
			printCursorIgnore(w)
		}
	}
	if !f.dryRun {
		fmt.Fprintln(w, "\nTo verify: keylatch doctor --agents")
	}
	return nil
}

func printCursorIgnore(w io.Writer) {
	fmt.Fprintln(w, "\nCursor does not currently enforce a beforeReadFile deny for agent reads, so the")
	fmt.Fprintln(w, "read hook is defence in depth only. Cursor's ignore files apply per project;")
	fmt.Fprintln(w, "add these patterns to each project's .cursorignore, or to the global ignore")
	fmt.Fprintln(w, "list in Cursor's user settings (the docs name no file path for it):")
	fmt.Fprintln(w)
	for _, pattern := range guard.CursorIgnorePatterns() {
		fmt.Fprintf(w, "  %s\n", pattern)
	}
}

var roleLabels = map[string]string{installer.RoleHook: "Hook", installer.RoleMCP: "MCP server", installer.RoleRules: "Rules"}

func roleLabel(roles []string) string {
	var labels []string
	for _, r := range roles {
		labels = append(labels, roleLabels[r])
	}
	return strings.Join(labels, " and ")
}

func printInstall(w io.Writer, res installer.Result, dryRun bool) {
	for _, c := range res.Changes {
		label := roleLabel(c.Roles)
		switch {
		case c.Changed && dryRun:
			fmt.Fprint(w, c.Diff)
		case c.Changed && c.Backup != "":
			fmt.Fprintf(w, "%s written to: %s (previous file saved as %s)\n", label, c.Path, c.Backup)
		case c.Changed:
			fmt.Fprintf(w, "%s written to: %s\n", label, c.Path)
		default:
			fmt.Fprintf(w, "%s already installed in: %s (use --upgrade to refresh it)\n", label, c.Path)
		}
	}
	for _, n := range res.Notes {
		fmt.Fprintf(w, "Note: %s\n", n)
	}
}

func runHarnessUninstall(cmd *cobra.Command, args []string, f installFlags) error {
	ds, err := harnessTargets(args, f.all)
	if err != nil {
		return err
	}
	var names []string
	for _, d := range ds {
		names = append(names, d.Name)
	}
	if _, err := requirePresence(cmd.Context(), presence.ActionGuardUninstall, "Remove the Keylatch integration from %s", strings.Join(names, ", ")); err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	for _, d := range ds {
		if d.Support != harness.SupportGuard {
			fmt.Fprintf(w, "%s: nothing to remove; Keylatch edits none of its files.\n", d.Name)
			continue
		}
		res, err := guard.UninstallHarness(d, installer.Options{Parts: f.parts}, f.opts())
		if err != nil {
			return fmt.Errorf("agent uninstall: %s: %w", d.ID, err)
		}
		if !res.Changed() {
			fmt.Fprintf(w, "No Keylatch integration found for %s.\n", d.Name)
			continue
		}
		for _, c := range res.Changes {
			switch {
			case c.Changed && f.dryRun:
				fmt.Fprint(w, c.Diff)
			case c.Changed:
				fmt.Fprintf(w, "%s removed from %s: %s\n", roleLabel(c.Roles), d.Name, c.Path)
			}
		}
	}
	return nil
}
