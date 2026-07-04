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
	{"CLAUDE_CODE", `set to "1" by Claude Code — enables LLM session guard`},
	{"CODEX_ENV", `set to "1" by Codex — enables LLM session guard`},
	{"CREDENTIALS_LLM_SESSION", `set to "1" to enable LLM session guard`},
	{"CURSOR_SESSION", `set to "1" by Cursor — enables LLM session guard`},
	{"AIDER_SESSION", `set by Aider to enable the Keylatch LLM session guard`},
	{"GEMINI_SESSION", `set by Gemini CLI to enable the Keylatch LLM session guard`},
	{"OPENCODE_SESSION", `set by OpenCode to enable the Keylatch LLM session guard`},
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
