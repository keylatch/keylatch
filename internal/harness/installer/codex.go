package installer

import (
	"strings"

	"github.com/keylatch/keylatch/internal/harness/merge"
)

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

// tomlKey writes a table name as a bare key when TOML allows it and quoted
// otherwise, so a connection name with a dot stays one key.
func tomlKey(name string) string {
	if strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") == "" {
		return name
	}
	return tomlString(name)
}

// codexServers is the config.toml tables that register the MCP servers.
func codexServers(entries []serverEntry) string {
	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("[mcp_servers." + tomlKey(e.name) + "]\ncommand = " + tomlString(e.server.Command) + "\nargs = " + tomlStrings(e.server.args()) + "\n")
	}
	return b.String()
}
