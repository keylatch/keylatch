package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// newPathsCmd returns the `keylatch paths` command.
// Shows all well-known keylatch filesystem paths.
func newPathsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "paths",
		Short: "Show well-known keylatch filesystem paths",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "config\t%s\n", paths.Config(env))
			fmt.Fprintf(w, "vault\t%s\n", paths.Vault(env))
			fmt.Fprintf(w, "audit log\t%s\n", paths.Audit(env))
			fmt.Fprintf(w, "gateway pid\t%s\n", paths.GatewayPID(env))
			fmt.Fprintf(w, "gateway log\t%s\n", paths.GatewayLog(env))
			return w.Flush()
		},
	}
}

// envEntry describes a known environment variable and its documentation.
type envEntry struct {
	Name        string
	Description string
}

// knownEnvVars is the ordered list of keylatch-relevant environment variables.
var knownEnvVars = []envEntry{
	{"KEYLATCH_BACKEND", "sets storage backend (file|keychain|op|bw)"},
	{"KEYLATCH_CONFIG_DIR", "override default config directory (~/.keylatch)"},
	{"KEYLATCH_VAULT_PATH", "overrides vault directory"},
	{"KEYLATCH_AUDIT_PATH", "overrides audit log path"},
	{"KEYLATCH_AUDIT_SALT_PATH", "overrides audit salt path"},
	{"KEYLATCH_MEMBER_ID", "your team member ID (for team commands)"},
	{"KEYLATCH_TEAM_DIR", "override team data directory"},
	{"KEYLATCH_OP_VAULT", "1Password vault name"},
	{"KEYLATCH_OP_BIN", "path to 1Password CLI binary"},
	{"BW_SESSION", "Bitwarden session token"},
	{"CLAUDECODE", `set to "1" by Claude Code in the shells it spawns — LLM session signal`},
	{"CLAUDE_CODE_ENTRYPOINT", "set by Claude Code — LLM session signal"},
	{"CODEX_SANDBOX", "set by Codex CLI under its macOS sandbox — LLM session signal"},
	{"CODEX_SANDBOX_NETWORK_DISABLED", "set by Codex CLI when network is disabled — LLM session signal"},
	{"CURSOR_AGENT", `set to "1" by the Cursor agent terminal — LLM session signal`},
	{"CURSOR_TRACE_ID", "set by Cursor — LLM session signal"},
	{"GEMINI_CLI", `set to "1" by Gemini CLI in shell commands — LLM session signal`},
	{"OPENCODE", `set to "1" by OpenCode — LLM session signal`},
	{"CREDENTIALS_LLM_SESSION", `set to "1" to mark a shell as an LLM session manually`},
	{"CLAUDE_CODE", "legacy alias for a manual LLM session label"},
	{"CODEX_ENV", "legacy alias for a manual LLM session label"},
	{"CURSOR_SESSION", "legacy alias for a manual LLM session label"},
	{"AIDER_SESSION", "manual LLM session label (Aider sets nothing)"},
	{"GEMINI_SESSION", "legacy alias for a manual LLM session label"},
	{"OPENCODE_SESSION", "legacy alias for a manual LLM session label"},
}

// newEnvCmd returns the `keylatch env` command.
// Documents recognized environment variables with current values if set.
func newEnvCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "env",
		Short: "Show recognized environment variables and their current values",
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			w := tabwriter.NewWriter(c.OutOrStdout(), 0, 0, 2, ' ', 0)
			for _, e := range knownEnvVars {
				current := env(e.Name)
				if current != "" {
					fmt.Fprintf(w, "%s\t%s [current: %s]\n", e.Name, e.Description, current)
				} else {
					fmt.Fprintf(w, "%s\t%s\n", e.Name, e.Description)
				}
			}
			return w.Flush()
		},
	}
}
