package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/allow"
	"github.com/spf13/cobra"
)

// agentProviderHints maps known agent names to the provider slugs they typically use.
// This is a static map for 0.1.0 — no external lookup needed.
var agentProviderHints = map[string][]string{
	"claude":        {"anthropic", "openrouter"},
	"aider":         {"openai", "anthropic"},
	"cursor-agent":  {"openai", "anthropic"},
	"copilot-agent": {"openai"},
	"gemini":        {"google-ai"},
}

// newAllowCmd returns the `allow` subcommand for managing per-run allowlist overrides.
func newAllowCmd() *cobra.Command {
	var suggestAgent string
	var suggestEnv bool

	cmd := &cobra.Command{
		Use:   "allow",
		Short: "Manage per-run allowlist overrides",
		Long: `Manage per-run allowlist overrides for keylatch run.

Use --suggest <agent> to get a suggested --allow list for a known AI agent.
Use --suggest-env to infer providers from environment variables and agent config.
The printed slugs can be passed directly to 'keylatch run --allow'.`,
		RunE: func(c *cobra.Command, _ []string) error {
			if suggestEnv {
				// Determine agent config path: default to ~/.claude/settings.json.
				home, err := os.UserHomeDir()
				agentConfigPath := ""
				if err == nil {
					agentConfigPath = filepath.Join(home, ".claude", "settings.json")
				}

				suggestions := allow.Suggest(agentConfigPath)
				if len(suggestions) == 0 {
					fmt.Fprintln(c.OutOrStdout(), "No providers detected from environment variables.")
					return nil
				}

				fmt.Fprintf(c.OutOrStdout(), "Suggested providers based on your environment: %s. Add all? (y/N/select)\n",
					strings.Join(suggestions, ", "))

				var input string
				if _, err := fmt.Fscan(c.InOrStdin(), &input); err != nil {
					input = ""
				}
				input = strings.TrimSpace(strings.ToLower(input))

				switch input {
				case "y":
					fmt.Fprintf(c.OutOrStdout(), "Adding all: %s\n", strings.Join(suggestions, ", "))
				case "", "n":
					fmt.Fprintln(c.OutOrStdout(), "Skipped.")
				default:
					// Treat input as space or comma-separated provider names.
					selected := strings.FieldsFunc(input, func(r rune) bool { return r == ',' || r == ' ' })
					fmt.Fprintf(c.OutOrStdout(), "Adding selected: %s\n", strings.Join(selected, ", "))
				}
				return nil
			}

			if suggestAgent == "" {
				// No flag provided — list all known agents.
				fmt.Fprintln(c.OutOrStdout(), "Known agent suggestions (use --suggest <agent>):")
				for agent, slugs := range agentProviderHints {
					fmt.Fprintf(c.OutOrStdout(), "  %-20s → %s\n", agent, strings.Join(slugs, ", "))
				}
				return nil
			}

			hints, ok := agentProviderHints[suggestAgent]
			if !ok {
				fmt.Fprintf(c.ErrOrStderr(), "No suggestion found for agent %q.\n\n", suggestAgent)
				fmt.Fprintln(c.ErrOrStderr(), "Known agents:")
				for agent := range agentProviderHints {
					fmt.Fprintf(c.ErrOrStderr(), "  %s\n", agent)
				}
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "Suggested allow list for %q: %s\n", suggestAgent, strings.Join(hints, ", "))
			allowFlags := make([]string, 0, len(hints))
			for _, slug := range hints {
				allowFlags = append(allowFlags, fmt.Sprintf("--allow %s", slug))
			}
			fmt.Fprintf(c.OutOrStdout(), "\n  keylatch run <connection> %s -- %s ...\n",
				strings.Join(allowFlags, " "), suggestAgent)
			return nil
		},
	}

	cmd.Flags().StringVar(&suggestAgent, "suggest", "", "print suggested allow list for the named AI agent")
	cmd.Flags().BoolVar(&suggestEnv, "suggest-env", false, "infer suggested providers from environment variables and agent config")

	return cmd
}
