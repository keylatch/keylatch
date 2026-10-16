package installer

import "github.com/keylatch/keylatch/internal/harness/merge"

// Copilot CLI reads ~/.copilot/hooks/*.json (version 1); the command runs
// through bash and the timeout is in seconds.
func copilotPlan() hookPlan {
	return hookPlan{
		container: "hooks",
		prepare:   setDefault("version", num(1)),
		entries: []hookEntry{{event: "preToolUse", build: func(command string) *merge.Object {
			return obj("type", "command", "bash", command, "timeoutSec", num(10))
		}}},
	}
}

// Antigravity reads a named hook set from hooks.json; the set is switched on
// with "enabled".
func antigravityPlan() hookPlan {
	return hookPlan{
		container:     "keylatch-guard",
		initContainer: func(c *merge.Object) { c.Set("enabled", true) },
		entries: []hookEntry{{event: "PreToolUse", build: func(command string) *merge.Object {
			return obj("matcher", "run_command|view_file", "hooks", []any{commandHook(command, "timeout", num(10))})
		}}},
	}
}

// Windsurf (Cascade) reads one command list per event from hooks.json; a hook
// that exits 2 blocks the action.
func windsurfPlan() hookPlan {
	entry := func(event string) hookEntry {
		return hookEntry{event: event, build: func(command string) *merge.Object {
			return obj("command", command, "show_output", false)
		}}
	}
	return hookPlan{
		container: "hooks",
		entries:   []hookEntry{entry("pre_run_command"), entry("pre_read_code"), entry("pre_write_code"), entry("pre_mcp_tool_use")},
	}
}

func setDefault(key string, v any) func(root *merge.Object) {
	return func(root *merge.Object) {
		if _, ok := root.Get(key); !ok {
			root.Set(key, v)
		}
	}
}
