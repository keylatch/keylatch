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
  cursor        PreToolUse hook in ~/.cursor/settings.json
  aider         pre-tool-use-hook in ~/.aider.conf.yml
  windsurf      Manual — set CREDENTIALS_LLM_SESSION=windsurf in shell rc
  codex         PreToolUse hook in ~/.codex/hooks.json
  copilot       Shell wrapper (patches shell rc to intercept copilot invocations)
  gemini        BeforeTool hook in ~/.gemini/settings.json
  opencode      TypeScript plugin (tool.execute.before hook)
  antigravity   Manual — set CREDENTIALS_LLM_SESSION=antigravity in shell rc

The guard is a shell script (or TypeScript plugin for opencode) that runs before
every tool call. It exits non-zero / throws when it detects credential exfiltration
patterns (keylatch get, security find-password, op read, etc.), causing the tool
call to be blocked by the agent.

Keylatch's own LLM-session guard (Layer 1) still applies even without this hook.
The hook provides a second layer of defence (Layer 2) at the agent framework level.

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
		agent = guard.AgentAider
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

	// Windsurf and Antigravity have no hook API — print shell-rc guidance and return.
	if agent == guard.AgentWindsurf {
		w := cmd.OutOrStdout()
		fmt.Fprintln(w, "To protect credentials in Windsurf integrated terminals, add this to your shell rc:")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  zsh/bash:   export CREDENTIALS_LLM_SESSION=windsurf")
		fmt.Fprintln(w, "  fish:       set -Ux CREDENTIALS_LLM_SESSION windsurf")
		fmt.Fprintln(w, "  PowerShell: [Environment]::SetEnvironmentVariable('CREDENTIALS_LLM_SESSION','windsurf','User')")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "After setting the variable, restart your terminal or reload your shell rc.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This triggers the LLM-session guard (Layer 1), blocking direct credential")
		fmt.Fprintln(w, "access via 'keylatch get' whenever Windsurf's integrated terminal is active.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "See: https://keylatch.dev/integrations/windsurf")
		return nil
	}
	if agent == guard.AgentAntigravity {
		w := cmd.OutOrStdout()
		fmt.Fprintln(w, "To protect credentials in Antigravity integrated terminals, add this to your shell rc:")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  zsh/bash:   export CREDENTIALS_LLM_SESSION=antigravity")
		fmt.Fprintln(w, "  fish:       set -Ux CREDENTIALS_LLM_SESSION antigravity")
		fmt.Fprintln(w, "  PowerShell: [Environment]::SetEnvironmentVariable('CREDENTIALS_LLM_SESSION','antigravity','User')")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "After setting the variable, restart your terminal or reload your shell rc.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "This triggers the LLM-session guard (Layer 1), blocking direct credential")
		fmt.Fprintln(w, "access via 'keylatch get' whenever Antigravity's integrated terminal is active.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "See: https://keylatch.dev/integrations/antigravity")
		return nil
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
	case guard.AgentAider:
		fmt.Fprintln(w, "Guard installed for Aider.")
		fmt.Fprintf(w, "Config updated: %s\n", settingsPath)
	case guard.AgentCodex:
		fmt.Fprintln(w, "Guard installed for Codex CLI.")
		fmt.Fprintf(w, "Hook written to: %s\n", settingsPath)
	case guard.AgentCopilot:
		fmt.Fprintln(w, "Installing shell wrapper for GitHub Copilot CLI.")
		fmt.Fprintln(w, "Wrapper intercepts copilot invocations.")
		if settingsPath != "" {
			fmt.Fprintf(w, "Shell RC patched: %s\n", settingsPath)
		}
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
