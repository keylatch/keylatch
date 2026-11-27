package installer

import "github.com/keylatch/keylatch/internal/harness/merge"

// Cursor reads ~/.cursor/hooks.json (version 1): the payload arrives as JSON on
// stdin and a hook that fails to run blocks the action (failClosed).
func cursorPlan() hookPlan {
	entry := func(event string) hookEntry {
		return hookEntry{event: event, build: func(command string) *merge.Object {
			return obj("command", command, "timeout", num(10), "failClosed", true)
		}}
	}
	return hookPlan{
		container: "hooks",
		prepare:   setDefault("version", num(1)),
		entries:   []hookEntry{entry("beforeShellExecution"), entry("beforeReadFile"), entry("beforeMCPExecution")},
	}
}

// legacyCursorSettings is the file an earlier release put the hook in, which
// Cursor does not read for hooks.
const legacyCursorSettings = "settings.json"
