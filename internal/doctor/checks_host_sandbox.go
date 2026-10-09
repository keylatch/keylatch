package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// sandboxExclusion is one Keylatch entry found in a Claude Code
// sandbox.excludedCommands list.
type sandboxExclusion struct {
	file    string
	pattern string
	runs    bool
}

// checkHostSandboxKeylatchExcluded fails when a Claude Code settings file
// excludes keylatch from the agent sandbox. An excluded `keylatch run` starts
// its child process outside the sandbox with credentials injected, so
// anything the child executes escapes containment.
func checkHostSandboxKeylatchExcluded(lookup llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		var found []sandboxExclusion
		var unreadable []string
		for _, f := range claudeSettingsFiles(lookup) {
			data, err := os.ReadFile(f.path)
			if err != nil {
				if !os.IsNotExist(err) {
					unreadable = append(unreadable, f.label)
				}
				continue
			}
			var settings struct {
				Sandbox struct {
					ExcludedCommands []string `json:"excludedCommands"`
				} `json:"sandbox"`
			}
			if json.Unmarshal(data, &settings) != nil {
				unreadable = append(unreadable, f.label)
				continue
			}
			for _, pattern := range settings.Sandbox.ExcludedCommands {
				if matches, runs := matchKeylatchExclusion(pattern); matches {
					found = append(found, sandboxExclusion{file: f.label, pattern: pattern, runs: runs})
				}
			}
		}

		st := Status{
			Name:    "host.sandbox.keylatch_excluded",
			Section: "environment",
			OK:      true,
			Tags:    []string{"host", "sandbox"},
		}

		if len(found) == 0 {
			st.Detail = "no Claude Code settings exclude keylatch from the sandbox"
			if len(unreadable) > 0 {
				st.Warn = true
				st.Detail += fmt.Sprintf(" (could not read: %s)", strings.Join(unreadable, ", "))
			}
			return st
		}

		var runExcluded bool
		var lines []string
		for _, e := range found {
			runExcluded = runExcluded || e.runs
			lines = append(lines, fmt.Sprintf("%s: %q", e.file, e.pattern))
		}
		st.Detail = "sandbox.excludedCommands contains keylatch: " + strings.Join(lines, "; ")

		if runExcluded {
			st.OK = false
			st.Fix = exclusionFix(found, "Excluding `keylatch run` starts its child process, and any project code it runs, outside the agent sandbox. Agents use `keylatch call`; run `keylatch run` yourself with `! keylatch run <connection> -- <command>`.")
			return st
		}

		st.Warn = true
		st.Fix = exclusionFix(found, "Excluded commands run outside the agent sandbox. Keep only what the current setup needs.")
		return st
	}
}

func exclusionFix(found []sandboxExclusion, why string) string {
	byFile := map[string][]string{}
	var order []string
	for _, e := range found {
		if _, ok := byFile[e.file]; !ok {
			order = append(order, e.file)
		}
		byFile[e.file] = append(byFile[e.file], fmt.Sprintf("%q", e.pattern))
	}
	var parts []string
	for _, file := range order {
		parts = append(parts, fmt.Sprintf("in %s remove %s from sandbox.excludedCommands", file, strings.Join(byFile[file], ", ")))
	}
	return strings.Join(parts, "; ") + ". " + why
}

type settingsFile struct {
	label string
	path  string
}

// claudeSettingsFiles lists the user, project and local Claude Code settings
// files. The project directory is CLAUDE_PROJECT_DIR when set, otherwise the
// working directory.
func claudeSettingsFiles(lookup llmcontext.Lookup) []settingsFile {
	var files []settingsFile

	userDir := lookup("CLAUDE_CONFIG_DIR")
	userLabel := filepath.Join(userDir, "settings.json")
	if userDir == "" {
		home := lookup("HOME")
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		if home != "" {
			userDir = filepath.Join(home, ".claude")
			userLabel = "~/.claude/settings.json"
		}
	}
	if userDir != "" {
		files = append(files, settingsFile{userLabel, filepath.Join(userDir, "settings.json")})
	}

	project := lookup("CLAUDE_PROJECT_DIR")
	if project == "" {
		project, _ = os.Getwd()
	}
	if project != "" {
		files = append(files,
			settingsFile{".claude/settings.json", filepath.Join(project, ".claude", "settings.json")},
			settingsFile{".claude/settings.local.json", filepath.Join(project, ".claude", "settings.local.json")},
		)
	}
	return files
}

// matchKeylatchExclusion reports whether an excludedCommands pattern targets
// the keylatch binary, and whether it covers the `run` subcommand.
func matchKeylatchExclusion(pattern string) (matches, coversRun bool) {
	p := strings.TrimSpace(pattern)
	prog, rest := p, ""
	if i := strings.IndexAny(p, " \t"); i >= 0 {
		prog, rest = p[:i], strings.TrimSpace(p[i+1:])
	} else if i := strings.Index(p, ":"); i >= 0 {
		prog, rest = p[:i], p[i+1:]
	}
	prog = strings.TrimSuffix(strings.TrimSuffix(prog, ":*"), "*")
	prog = strings.TrimSuffix(prog, ".exe")
	if filepath.Base(filepath.ToSlash(prog)) != "keylatch" {
		return false, false
	}
	verb := strings.TrimSpace(strings.SplitN(strings.TrimSuffix(rest, "*"), ":", 2)[0])
	verb = strings.SplitN(verb, " ", 2)[0]
	return true, verb == "" || verb == "run"
}
