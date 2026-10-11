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

// checkHostSandboxKeylatchExcluded fails when a Claude Code settings file
// excludes keylatch from the agent sandbox. An excluded `keylatch run` or
// `keylatch launch` starts its child process outside the sandbox with
// credentials injected, so anything the child executes escapes containment.
func checkHostSandboxKeylatchExcluded(lookup llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		var found []sandboxExclusion
		var checked, unreadable []string
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
		files = append(files, settingsFile{userLabel, filepath.Join(userDir, "settings.json"), false})
	}

	cwd, _ := os.Getwd()
	project := lookup("CLAUDE_PROJECT_DIR")
	if project == "" {
		project = cwd
	}
	if project != "" {
		settingsLabel := filepath.Join(project, ".claude", "settings.json")
		localLabel := filepath.Join(project, ".claude", "settings.local.json")
		if project == cwd {
			settingsLabel, localLabel = ".claude/settings.json", ".claude/settings.local.json"
		}
		files = append(files,
			settingsFile{settingsLabel, filepath.Join(project, ".claude", "settings.json"), false},
			settingsFile{localLabel, filepath.Join(project, ".claude", "settings.local.json"), false},
		)
	}
	return files, project
}

// keylatchSafeVerbs are top-level subcommands that start no child process
// chosen by their arguments. `doctor` runs fixed probes such as
// `<bin> --version`, which the caller cannot redirect. Every other verb is
// treated as able to run arbitrary commands, since `run` and `launch` execute
// their argv outside the sandbox when excluded.
var keylatchSafeVerbs = map[string]bool{
	"actors": true, "approve": true, "audit": true, "call": true, "check-expiry": true,
	"completion": true, "config": true, "connections": true, "deny": true,
	"describe": true, "doctor": true, "env": true, "grant": true, "health": true,
	"help-topic": true, "list": true, "mint": true, "modes": true, "paths": true,
	"policy": true, "projects": true, "receipts": true, "recipes": true,
	"registry": true, "rules": true, "scope": true, "security": true, "share": true,
	"status": true, "validate": true, "version": true, "versions": true,
}

// matchKeylatchExclusion reports whether an excludedCommands pattern targets
// the keylatch binary, and whether it can cover a child-spawning subcommand.
// Anything that is not a literal known non-spawning verb counts as covering
// one: an empty verb, leading flags, and glob characters.
func matchKeylatchExclusion(pattern string) (matches, coversRun bool) {
	return matchKeylatchExclusionOn(runtime.GOOS, pattern)
}

// matchKeylatchExclusionOn matches the program name case-insensitively on
// the platforms whose filesystems are.
func matchKeylatchExclusionOn(goos, pattern string) (matches, coversRun bool) {
	p := strings.TrimSpace(pattern)
	prog, rest := splitProgram(p)
	prog = strings.TrimSuffix(prog, "*")
	prog = strings.ReplaceAll(prog, `\`, "/")
	base := path.Base(prog)
	if len(base) > 4 && strings.EqualFold(base[len(base)-4:], ".exe") {
		base = base[:len(base)-4]
	}
	if goos == "darwin" || goos == "windows" {
		base = strings.ToLower(base)
	}
	if base != "keylatch" {
		return false, false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
	verb, _, _ := strings.Cut(strings.Join(strings.Fields(rest), " "), " ")
	verb, _, _ = strings.Cut(verb, ":")
	if verb == "" || strings.HasPrefix(verb, "-") || strings.ContainsAny(verb, "*?[") {
		return true, true
	}
	return true, !keylatchSafeVerbs[verb]
}

// splitProgram separates the program from the arguments. A leading quoted
// token is the program; otherwise it ends at the first whitespace, and a rule
// separator `:` only counts after the last path separator so drive letters
// are not mistaken for it.
func splitProgram(p string) (prog, rest string) {
	if p != "" && (p[0] == '"' || p[0] == '\'') {
		if end := strings.IndexByte(p[1:], p[0]); end >= 0 {
			return p[1 : 1+end], p[2+end:]
		}
	}
	token, tail := p, ""
	if i := strings.IndexAny(p, " \t"); i >= 0 {
		token, tail = p[:i], p[i:]
	}
	sep := strings.LastIndexAny(token, `/\`)
	if i := strings.IndexByte(token[sep+1:], ':'); i >= 0 {
		i += sep + 1
		return token[:i], token[i+1:] + tail
	}
	return token, tail
}
