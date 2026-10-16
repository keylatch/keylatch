package installer

import "github.com/keylatch/keylatch/internal/harness/merge"

// Codex reads hooks.json as an object keyed by event; each event holds
// matcher groups. The tool Keylatch guards is the shell. Non-managed hooks need
// the user's review (/hooks in Codex) before they run.
func codexPlan() hookPlan {
	return hookPlan{
		container: "hooks",
		entries: []hookEntry{{event: "PreToolUse", build: func(command string) *merge.Object {
			return obj("matcher", "Bash", "hooks", []any{commandHook(command, "timeout", num(30))})
		}}},
	}
}

// codexServer is the config.toml table that registers the MCP server.
func codexServer(s Server) string {
	return "[mcp_servers.keylatch]\ncommand = " + tomlString(s.Command) + "\nargs = " + tomlStrings(s.args()) + "\n"
}
