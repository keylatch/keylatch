package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/harness/sandbox"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// sandboxExclusion is one Keylatch entry found in a Claude Code
// sandbox.excludedCommands list.
type sandboxExclusion struct {
	file    string
	pattern string
	runs    bool
	managed bool
}

// SandboxExclusion is a keylatch entry in a Claude Code settings file's
// sandbox.excludedCommands list.
type SandboxExclusion struct {
	File    string
	Pattern string
	// RunsChildren is true when the entry can cover a subcommand that starts a
	// process of the caller's choosing (`run`, `launch`).
	RunsChildren bool
	// Managed is true for administrator-managed settings.
	Managed bool
}

// ClaudeCodeExclusions lists the keylatch entries of every Claude Code settings
// file, and the files that could not be read.
func ClaudeCodeExclusions(lookup llmcontext.Lookup) (found []SandboxExclusion, unreadable []string) {
	exclusions, _, unreadable, _ := scanExclusions(lookup)
	for _, e := range exclusions {
		found = append(found, SandboxExclusion{File: e.file, Pattern: e.pattern, RunsChildren: e.runs, Managed: e.managed})
	}
	return found, unreadable
}

// scanExclusions reads every Claude Code settings file for keylatch entries in
// sandbox.excludedCommands.
func scanExclusions(lookup llmcontext.Lookup) (found []sandboxExclusion, checked, unreadable []string, projectDir string) {
	files, projectDir := claudeSettingsFiles(lookup)
	for _, f := range files {
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
		checked = append(checked, f.label)
		for _, pattern := range settings.Sandbox.ExcludedCommands {
			if matches, runs := matchKeylatchExclusion(pattern); matches {
				found = append(found, sandboxExclusion{file: f.label, pattern: pattern, runs: runs, managed: f.managed})
			}
		}
	}
	return found, checked, unreadable, projectDir
}

// checkHostSandboxKeylatchExcluded fails when a Claude Code settings file
// excludes keylatch from the agent sandbox. An excluded `keylatch run` or
// `keylatch launch` starts its child process outside the sandbox with
// credentials injected, so anything the child executes escapes containment.
func checkHostSandboxKeylatchExcluded(lookup llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		found, checked, unreadable, projectDir := scanExclusions(lookup)

		st := Status{
			Name:    "host.sandbox.keylatch_excluded",
			Section: "environment",
			OK:      true,
			Tags:    []string{"host", "sandbox"},
		}
		skipped := ""
		if len(unreadable) > 0 {
			skipped = fmt.Sprintf(" (could not read: %s)", strings.Join(unreadable, ", "))
		}

		if len(found) == 0 {
			st.Detail = "no excluded keylatch commands in Claude Code settings"
			if projectDir != "" {
				st.Detail += fmt.Sprintf(" (project directory %s)", projectDir)
			}
			if len(checked) > 0 {
				st.Detail += "; checked " + strings.Join(checked, ", ")
			} else {
				st.Detail += "; no settings files found"
			}
			st.Detail += skipped
			st.Warn = len(unreadable) > 0
			return st
		}

		var runExcluded bool
		var lines []string
		for _, e := range found {
			runExcluded = runExcluded || e.runs
			lines = append(lines, fmt.Sprintf("%s: %q", e.file, e.pattern))
		}
		st.Detail = "sandbox.excludedCommands contains keylatch: " + strings.Join(lines, "; ") + skipped

		if runExcluded {
			st.OK = false
			st.Fix = exclusionFix(found, "Excluding `keylatch run` or `keylatch launch` starts its child process, and any project code it runs, outside the agent sandbox. Agents use `keylatch call`; run `keylatch run` yourself with `! keylatch run <connection> -- <command>`.")
			return st
		}

		st.Warn = true
		st.Fix = exclusionFix(found, "Excluded commands run outside the agent sandbox. Keep only what the current setup needs.")
		return st
	}
}

func exclusionFix(found []sandboxExclusion, why string) string {
	byFile := map[string][]sandboxExclusion{}
	var order []string
	for _, e := range found {
		if _, ok := byFile[e.file]; !ok {
			order = append(order, e.file)
		}
		byFile[e.file] = append(byFile[e.file], e)
	}
	var parts []string
	for _, file := range order {
		var quoted []string
		for _, e := range byFile[file] {
			quoted = append(quoted, fmt.Sprintf("%q", e.pattern))
		}
		list := strings.Join(quoted, ", ")
		if byFile[file][0].managed {
			parts = append(parts, fmt.Sprintf("%s is administrator-managed: ask the administrator to remove %s from sandbox.excludedCommands", file, list))
		} else {
			parts = append(parts, fmt.Sprintf("in %s remove %s from sandbox.excludedCommands", file, list))
		}
	}
	return strings.Join(parts, "; ") + ". " + why
}

type settingsFile struct {
	label   string
	path    string
	managed bool
}

// managedSettingsDir returns the system directory Claude Code reads
// administrator-managed settings from.
var managedSettingsDir = defaultManagedSettingsDir

// OverrideManagedSettingsDir points the managed settings lookup at dir and
// returns a func that restores the previous lookup. Tests use it so a
// developer's real managed settings never affect results.
func OverrideManagedSettingsDir(dir string) func() {
	prev := managedSettingsDir
	managedSettingsDir = func() string { return dir }
	return func() { managedSettingsDir = prev }
}

func defaultManagedSettingsDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "windows":
		return `C:\Program Files\ClaudeCode`
	default:
		return "/etc/claude-code"
	}
}

// claudeSettingsFiles lists the managed, user, project and local Claude Code
// settings files, and the project directory they were derived from. The
// project directory is CLAUDE_PROJECT_DIR when set, otherwise the working
// directory.
func claudeSettingsFiles(lookup llmcontext.Lookup) ([]settingsFile, string) {
	var files []settingsFile

	if dir := managedSettingsDir(); dir != "" {
		files = append(files, settingsFile{filepath.Join(dir, "managed-settings.json"), filepath.Join(dir, "managed-settings.json"), true})
		dropDir := filepath.Join(dir, "managed-settings.d")
		entries, err := os.ReadDir(dropDir)
		if err != nil && !os.IsNotExist(err) {
			files = append(files, settingsFile{dropDir, dropDir, true})
		}
		var drops []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				drops = append(drops, filepath.Join(dropDir, e.Name()))
			}
		}
		sort.Strings(drops)
		for _, d := range drops {
			files = append(files, settingsFile{d, d, true})
		}
	}

	claude, _ := harness.Lookup("claude-code")
	home := lookup("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	configDir := lookup(claude.Config.Env)
	if configDir != "" || home != "" {
		userPath := claude.Layout(harness.Env{Home: home, Getenv: lookup}).Hook
		userLabel := userPath
		if configDir == "" {
			userLabel = claude.HookDisplay()
		}
		files = append(files, settingsFile{userLabel, userPath, false})
	}

	cwd, _ := os.Getwd()
	project := lookup("CLAUDE_PROJECT_DIR")
	if project == "" {
		project = cwd
	}
	if project != "" {
		const localName = "settings.local.json"
		settings := claude.Layout(harness.Env{Project: project}).Hook
		settingsLabel, localLabel := settings, filepath.Join(filepath.Dir(settings), localName)
		if project == cwd {
			settingsLabel = claude.Hook.ProjectFile
			localLabel = path.Join(path.Dir(claude.Hook.ProjectFile), localName)
		}
		files = append(files,
			settingsFile{settingsLabel, settings, false},
			settingsFile{localLabel, filepath.Join(filepath.Dir(settings), localName), false},
		)
	}
	return files, project
}

var (
	matchKeylatchExclusion   = sandbox.MatchKeylatch
	matchKeylatchExclusionOn = sandbox.MatchKeylatchOn
)
