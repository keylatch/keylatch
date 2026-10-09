package cli

// install_guard_cmd.go implements `keylatch install-guard <agent>`.

import (
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/guard"
	"github.com/spf13/cobra"
)

// newInstallGuardCmd returns the `keylatch install-guard` command.
// §4.2: surfaces the agent exfiltration guard for one-command installation.
func newInstallGuardCmd() *cobra.Command {
	var project bool
	var list bool

	cmd := &cobra.Command{
		Use:   "install-guard <agent>",
		Short: "Install an agent exfiltration guard",
		Long: `Install a pre-tool-use hook that blocks credential exfiltration attempts
from an LLM agent. Supported agents:

  claude-code   PreToolUse hook in ~/.claude/settings.json
  cursor        beforeShellExecution and beforeReadFile hooks in ~/.cursor/hooks.json
  windsurf      pre_run_command and pre_read_code hooks in ~/.codeium/windsurf/hooks.json
  codex         PreToolUse hook in ~/.codex/hooks.json (review it with /hooks in Codex)
  copilot       PreToolUse hook in ~/.copilot/hooks/keylatch-guard.json
  gemini        BeforeTool hook in ~/.gemini/settings.json
  opencode      TypeScript plugin (tool.execute.before hook)
  antigravity   PreToolUse hook in ~/.gemini/config/hooks.json

The guard is a shell script (or TypeScript plugin for opencode) that runs before
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
			return runInstallGuard(cmd, args[0], project)
		},
	}

	cmd.Flags().BoolVar(&project, "project", false,
		"install into .claude/settings.json in the current directory instead of global (claude-code only)")
	cmd.Flags().BoolVar(&list, "list", false,
		"list all supported agents with their hook mechanism type")

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

func runInstallGuard(cmd *cobra.Command, agentName string, project bool) error {
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
		return fmt.Errorf("install-guard: aider has no hook API; start it with 'keylatch launch -- aider'")
	case "windsurf":
		agent = guard.AgentWindsurf
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
		return fmt.Errorf(
			"install-guard: unknown agent %q\n\nSupported agents: %s\n\nExample: keylatch install-guard claude-code\nUse --list for details",
			agentName, strings.Join(supported, ", "),
		)
	}

	opts := guard.InstallOpts{}
	if project {
		opts.ProjectDir = "."
	}

	settingsPath, err := guard.Install(agent, opts)
	if err != nil {
		return fmt.Errorf("install-guard: %w", err)
	}

	w := cmd.OutOrStdout()
	switch agent {
	case guard.AgentClaudeCode:
		fmt.Fprintln(w, "Guard installed for Claude Code.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
		fmt.Fprintln(w, "Run 'keylatch install-guard claude-code' again to update.")
	case guard.AgentCursor:
		fmt.Fprintln(w, "Guard installed for Cursor.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
		fmt.Fprintln(w, "\nCursor does not currently enforce a beforeReadFile deny for agent reads, so the")
		fmt.Fprintln(w, "read hook is defence in depth only. Cursor's ignore files apply per project;")
		fmt.Fprintln(w, "add these patterns to each project's .cursorignore, or to the global ignore")
		fmt.Fprintln(w, "list in Cursor's user settings (the docs name no file path for it):")
		fmt.Fprintln(w)
		for _, pattern := range guard.CursorIgnorePatterns {
			fmt.Fprintf(w, "  %s\n", pattern)
		}
	case guard.AgentWindsurf:
		fmt.Fprintln(w, "Guard installed for Windsurf.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
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
