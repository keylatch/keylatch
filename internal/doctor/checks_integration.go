package doctor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// integrationConfig is the path (relative to cwd) where the Keylatch
// integration config lives when set up via `keylatch init integration --agent`.
const integrationConfig = ".keylatch/integration.yml"

// agentMarker pairs a filesystem path (relative to cwd) with the agent name
// it signals and the doc link for that agent.
type agentMarker struct {
	path  string
	agent string
	doc   string
}

// agentMarkers is the ordered list of known agent marker paths.
// A file or directory matching path signals that the given agent is in use.
var agentMarkers = []agentMarker{
	{".claude/settings.json", "claude-code", "docs/integration/agents/claude-code.md"},
	{"CLAUDE.md", "claude-code", "docs/integration/agents/claude-code.md"},
	{".windsurf/hooks", "windsurf", "docs/integration/agents/windsurf.md"},
	{".cursor/rules", "cursor", "docs/integration/agents/cursor.md"},
	{"AGENTS.md", "generic", "docs/integration/agents/generic.md"},
	{".gemini/config.yml", "gemini", "docs/integration/agents/gemini.md"},
	{".gemini/settings.json", "gemini", "docs/integration/agents/gemini.md"},
}

// checkIntegrationMarkers implements the I3: integration-markers doctor check.
//
// It walks the current working directory looking for known agent marker files.
// If any markers are found but .keylatch/integration.yml is absent, it emits a
// warning with a link to the relevant integration guide. If the integration
// config exists, the check passes.
//
// Security invariant: the check is value-free — it only tests for path
// existence, never reads file contents or emits credential-adjacent data.
func checkIntegrationMarkers() Check {
	return func(_ context.Context) Status {
		const checkName = "I3 integration-markers"
		const section = "environment"

		cwd, err := os.Getwd()
		if err != nil {
			return Status{
				Name:    checkName,
				Section: section,
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("I3: could not determine working directory: %v", err),
				Tags:    []string{"integration"},
			}
		}

		// Check whether .keylatch/integration.yml exists.
		integrationPath := filepath.Join(cwd, integrationConfig)
		integrationExists := pathExists(integrationPath)

		if integrationExists {
			return Status{
				Name:    checkName,
				Section: section,
				OK:      true,
				Detail:  fmt.Sprintf("I3: integration config found at %s", integrationConfig),
				Tags:    []string{"integration"},
			}
		}

		// Scan for agent markers.
		detected := findAgentMarkers(cwd)

		if len(detected) == 0 {
			// No markers found — no action needed.
			return Status{
				Name:    checkName,
				Section: section,
				OK:      true,
				Detail:  "I3: no agent markers detected in current directory",
				Tags:    []string{"integration"},
			}
		}

		// Build a concise warning message.
		first := detected[0]
		detail := fmt.Sprintf(
			"I3: agent marker detected (%s → %s) but no Keylatch integration config found",
			first.path, first.agent,
		)
		if len(detected) > 1 {
			detail += fmt.Sprintf(" (and %d more)", len(detected)-1)
		}

		fix := fmt.Sprintf(
			"run 'keylatch init integration --agent %s' to scaffold integration config; "+
				"see %s",
			first.agent,
			first.doc,
		)

		return Status{
			Name:    checkName,
			Section: section,
			OK:      true,
			Warn:    true,
			Detail:  detail,
			Fix:     fix,
			Tags:    []string{"integration"},
		}
	}
}

// findAgentMarkers returns the subset of agentMarkers whose paths exist under root.
func findAgentMarkers(root string) []agentMarker {
	var found []agentMarker
	seen := map[string]bool{}
	for _, m := range agentMarkers {
		if seen[m.agent] {
			continue // report each agent at most once
		}
		full := filepath.Join(root, m.path)
		if pathExists(full) {
			found = append(found, m)
			seen[m.agent] = true
		}
	}
	return found
}

// pathExists returns true if path exists (file or directory).
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
