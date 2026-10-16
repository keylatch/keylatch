package cli

// install_guard_cmd.go implements `keylatch install-guard <agent>`.

import (
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/spf13/cobra"
)

// newInstallGuardCmd returns the `keylatch install-guard` command.
// §4.2: surfaces the agent exfiltration guard for one-command installation.
func newInstallGuardCmd() *cobra.Command {
	var project, list, uninstall bool

	cmd := &cobra.Command{
		Use:   "install-guard <agent>",
		Short: "Install an agent exfiltration guard",
		Long: `Install a pre-tool-use hook that blocks credential exfiltration attempts
from an LLM agent. Supported agents:

  claude-code   PreToolUse hook in ~/.claude/settings.json
  cursor        beforeShellExecution and beforeReadFile hooks in ~/.cursor/hooks.json
  codex         PreToolUse hook in ~/.codex/hooks.json (review it with /hooks in Codex)
  copilot       PreToolUse hook in ~/.copilot/hooks/keylatch-guard.json
  gemini        BeforeTool hook in ~/.gemini/settings.json
  opencode      TypeScript plugin (tool.execute.before hook)
  antigravity   PreToolUse hook in ~/.gemini/config/hooks.json

For Claude Code the guard is 'keylatch guard hook --harness claude-code': it parses
each shell command and checks each file tool's paths, and denies on a credential
read, a secret-manager call or an environment dump (exit 2 plus the deny JSON).
install-guard merges it into ~/.claude/settings.json and, when set,
$CLAUDE_CONFIG_DIR/settings.json, keeping every other setting and hook; --config-dir
adds directories, --upgrade refreshes an installed entry, --dry-run prints a diff.
The previous file is saved as settings.json.keylatch.bak.

The other harnesses run a shell script (or a TypeScript plugin for opencode) before
every tool call. When it detects a credential exfiltration pattern (keylatch get,
secret-manager reads, env dumps, direnv/mise/atuin dumps, ...) it exits 2 and
prints the harness's deny JSON, which blocks the tool call.

Keylatch's own LLM-session guard (Layer 1) still applies even without this hook.
The hook provides a second layer of defence (Layer 2) at the agent framework level.

Aider has no hook API; start it with 'keylatch launch -- aider'.

Use --list to show all supported agents with their hook mechanism type.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if list {
				return runInstallGuardList(cmd)
			}
			if len(args) == 0 {
				return fmt.Errorf("install-guard: agent name required (use --list to see available agents)")
			}
			if uninstall {
				return runUninstallGuard(cmd, args[0], project)
			}
			return runInstallGuard(cmd, args[0], project)
		},
	}

	cmd.Flags().BoolVar(&uninstall, "uninstall", false,
		"remove the guard hook and script (needs a human at a terminal)")
	cmd.Flags().BoolVar(&project, "project", false,
		"install into .claude/settings.json in the current directory instead of global (claude-code only)")
	cmd.Flags().BoolVar(&list, "list", false,
		"list all supported agents with their hook mechanism type")
	cmd.Flags().Bool("upgrade", false,
		"refresh an installed guard entry in place: new binary path, matcher and timeout (claude-code only)")
	cmd.Flags().Bool("dry-run", false,
		"print a unified diff of the change and write nothing (claude-code only)")
	cmd.Flags().StringSlice("config-dir", nil,
		"also install into this Claude Code configuration directory; repeatable (claude-code only)")

	return cmd
}

func runInstallGuardList(cmd *cobra.Command) error {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Supported agents for keylatch install-guard:")
	fmt.Fprintln(w)
	for _, a := range guard.SupportedAgents {
		mechanism := guard.AgentHookMechanism[a]
		fmt.Fprintf(w, "  %-15s  %s\n", string(a), mechanism)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Example: keylatch install-guard claude-code")
	return nil
}

func runUninstallGuard(cmd *cobra.Command, agentName string, project bool) error {
	agent, err := parseGuardAgent(agentName)
	if err != nil {
		return err
	}
	if _, err := requirePresence(cmd.Context(), presence.ActionGuardUninstall, "Remove the %s exfiltration guard", agent); err != nil {
		return err
	}
	opts := guard.InstallOpts{}
	if project {
		opts.ProjectDir = "."
	}
	path, removed, err := guard.Uninstall(agent, opts)
	if err != nil {
		return err
	}
	if !removed {
		fmt.Fprintf(cmd.OutOrStdout(), "No %s guard found.\n", agent)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Guard removed for %s (%s).\n", agent, path)
	return nil
}

func parseGuardAgent(agentName string) (guard.Agent, error) {
	agentName = strings.ToLower(strings.TrimSpace(agentName))

	// Normalise common aliases.
	switch agentName {
	case "claude_code", "claudecode":
		agentName = "claude-code"
	case "claude-code":
		// ok
	}

	var agent guard.Agent
	switch agentName {
	case "claude-code":
		agent = guard.AgentClaudeCode
	case "cursor":
		agent = guard.AgentCursor
	case "aider":
		return "", fmt.Errorf("install-guard: aider has no hook API; start it with 'keylatch launch -- aider'")
	case "codex":
		agent = guard.AgentCodex
	case "copilot":
		agent = guard.AgentCopilot
	case "gemini":
		agent = guard.AgentGemini
	case "opencode":
		agent = guard.AgentOpenCode
	case "antigravity":
		agent = guard.AgentAntigravity
	default:
		supported := make([]string, 0, len(guard.SupportedAgents))
		for _, a := range guard.SupportedAgents {
			supported = append(supported, string(a))
		}
		return "", fmt.Errorf(
			"install-guard: unknown agent %q\n\nSupported agents: %s\n\nExample: keylatch install-guard claude-code\nUse --list for details",
			agentName, strings.Join(supported, ", "),
		)
	}
	return agent, nil
}

// runInstallClaudeGuard merges the Go guard into every Claude Code settings
// file, or with --dry-run prints what it would change.
func runInstallClaudeGuard(cmd *cobra.Command, opts guard.InstallOpts) error {
	changes, err := guard.InstallClaudeCode(opts)
	if err != nil {
		return fmt.Errorf("install-guard: %w", err)
	}
	w := cmd.OutOrStdout()
	for _, c := range changes {
		switch {
		case c.Changed && opts.DryRun:
			fmt.Fprint(w, c.Diff)
		case c.Changed && c.Backup != "":
			fmt.Fprintf(w, "Hook written to: %s (previous file saved as %s)\n", c.Path, c.Backup)
		case c.Changed:
			fmt.Fprintf(w, "Hook written to: %s\n", c.Path)
		default:
			fmt.Fprintf(w, "Hook already installed in: %s (use --upgrade to refresh it)\n", c.Path)
		}
	}
	if !opts.DryRun {
		fmt.Fprintln(w, "\nTo verify: keylatch doctor")
	}
	return nil
}

func runInstallGuard(cmd *cobra.Command, agentName string, project bool) error {
	agent, err := parseGuardAgent(agentName)
	if err != nil {
		return err
	}

	opts := guard.InstallOpts{}
	if project {
		opts.ProjectDir = "."
	}
	opts.Upgrade, _ = cmd.Flags().GetBool("upgrade")
	opts.DryRun, _ = cmd.Flags().GetBool("dry-run")
	opts.ConfigDirs, _ = cmd.Flags().GetStringSlice("config-dir")
	if agent != guard.AgentClaudeCode && (opts.Upgrade || opts.DryRun || len(opts.ConfigDirs) > 0) {
		return fmt.Errorf("install-guard: --upgrade, --dry-run and --config-dir apply to claude-code only")
	}
	if agent == guard.AgentClaudeCode {
		return runInstallClaudeGuard(cmd, opts)
	}

	settingsPath, err := guard.Install(agent, opts)
	if err != nil {
		return fmt.Errorf("install-guard: %w", err)
	}

	w := cmd.OutOrStdout()
	switch agent {
	case guard.AgentCursor:
		fmt.Fprintln(w, "Guard installed for Cursor.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
		fmt.Fprintln(w, "\nCursor does not currently enforce a beforeReadFile deny for agent reads, so the")
		fmt.Fprintln(w, "read hook is defence in depth only. Cursor's ignore files apply per project;")
		fmt.Fprintln(w, "add these patterns to each project's .cursorignore, or to the global ignore")
		fmt.Fprintln(w, "list in Cursor's user settings (the docs name no file path for it):")
		fmt.Fprintln(w)
		for _, pattern := range guard.CursorIgnorePatterns() {
			fmt.Fprintf(w, "  %s\n", pattern)
		}
	case guard.AgentAntigravity:
		fmt.Fprintln(w, "Guard installed for Antigravity.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
	case guard.AgentCodex:
		fmt.Fprintln(w, "Guard installed for Codex CLI.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
		fmt.Fprintln(w, "Review and trust the hook with /hooks in Codex before it runs.")
	case guard.AgentCopilot:
		fmt.Fprintln(w, "Guard installed for GitHub Copilot CLI.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
	case guard.AgentGemini:
		fmt.Fprintln(w, "Guard installed for Gemini CLI.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
	case guard.AgentOpenCode:
		fmt.Fprintln(w, "Guard installed for OpenCode.")
		fmt.Fprintf(w, "Config updated: %s\n", settingsPath)
	}
	fmt.Fprintln(w, "\nTo verify: keylatch doctor")
	return nil
}
