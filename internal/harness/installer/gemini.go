package installer

import "github.com/keylatch/keylatch/internal/harness/merge"

// geminiMatcher selects the Gemini tools the guard sees: the shell and every
// tool that reads or writes file content.
const geminiMatcher = "run_shell_command|read_file|read_many_files|glob|search_file_content|grep_search|list_directory|write_file|replace"

// Gemini CLI reads hooks.BeforeTool from settings.json as matcher groups; the
// timeout is in milliseconds.
func geminiPlan() hookPlan {
	return hookPlan{
		container: "hooks",
		entries: []hookEntry{{event: "BeforeTool", build: func(command string) *merge.Object {
			return obj("matcher", geminiMatcher, "hooks", []any{commandHook(command, "name", "keylatch-guard", "timeout", num(10000))})
		}}},
	}
}
