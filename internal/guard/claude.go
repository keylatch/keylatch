package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/keylatch/keylatch/internal/harness"
)

// ClaudeChange is the outcome of installing the guard into one Claude Code
// settings file.
type ClaudeChange struct {
	// Path is the settings file.
	Path string
	// Changed is true when the file was (or, in a dry run, would be) rewritten.
	Changed bool
	// Diff is a unified diff of the change, set when Changed.
	Diff string
	// Backup is the copy of the previous file written before the change.
	Backup string
}

// ClaudeSettingsPaths lists the settings files an install writes: the project's
// when ProjectDir is set, otherwise ~/.claude, $CLAUDE_CONFIG_DIR when set, and
// every ConfigDirs entry.
func ClaudeSettingsPaths(opts InstallOpts) ([]string, error) {
	d, _ := harness.Lookup(string(AgentClaudeCode))
	if opts.ProjectDir != "" {
		return []string{d.Layout(harness.Env{Project: opts.ProjectDir}).Hook}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("install-guard: cannot determine home directory: %w", err)
	}
	defaultDir := d.Dir(harness.Env{Home: home, Getenv: func(string) string { return "" }})
	dirs := append([]string{defaultDir, d.Dir(harness.Env{Home: home})}, opts.ConfigDirs...)
	seen := map[string]bool{}
	var out []string
	for _, dir := range dirs {
		if dir = strings.TrimSpace(dir); dir == "" {
			continue
		}
		p := filepath.Join(filepath.Clean(dir), filepath.FromSlash(d.Hook.File))
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// claudeCommand is the hook command line: the absolute Keylatch binary, quoted
// so a path with a space survives the harness's shell.
func claudeCommand(opts InstallOpts) (string, error) {
	bin := opts.KeylatchPath
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("install-guard: cannot locate the keylatch binary: %w", err)
		}
		bin = exe
	}
	bin, err := filepath.Abs(bin)
	if err != nil {
		return "", fmt.Errorf("install-guard: cannot resolve the keylatch binary path: %w", err)
	}
	if runtime.GOOS == "windows" {
		bin = filepath.ToSlash(bin)
	}
	return quoteArg(bin) + claudeGuardSuffix, nil
}

// InstallClaudeCode merges the guard hook into every Claude Code settings file
// named by ClaudeSettingsPaths. Existing keys and hooks are kept. Before a
// file that exists is rewritten its previous content is saved next to it as
// settings.json.keylatch.bak. With DryRun nothing is written and each change
// carries its diff.
func InstallClaudeCode(opts InstallOpts) ([]ClaudeChange, error) {
	paths, err := ClaudeSettingsPaths(opts)
	if err != nil {
		return nil, err
	}
	command, err := claudeCommand(opts)
	if err != nil {
		return nil, err
	}
	changes := make([]ClaudeChange, 0, len(paths))
	for _, path := range paths {
		change, err := installClaudeFile(path, command, opts)
		if err != nil {
			return changes, err
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func installClaudeFile(path, command string, opts InstallOpts) (ClaudeChange, error) {
	change := ClaudeChange{Path: path}
	before, err := os.ReadFile(path) //nolint:gosec // G304: the agent's own settings file
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return change, fmt.Errorf("install-guard: read settings %q: %w", path, err)
	}
	settings, err := loadSettings(path)
	if err != nil {
		return change, err
	}
	changed, err := mergeClaudeGuard(settings, command, opts.Upgrade)
	if err != nil {
		return change, fmt.Errorf("install-guard: %s: %w", path, err)
	}
	if !changed {
		return change, nil
	}
	after, err := encodeSettings(settings)
	if err != nil {
		return change, err
	}
	change.Changed, change.Diff = true, unifiedDiff(path, before, after)
	if opts.DryRun {
		return change, nil
	}
	if exists {
		change.Backup = path + ".keylatch.bak"
		if err := os.WriteFile(change.Backup, before, 0o600); err != nil {
			return change, fmt.Errorf("install-guard: write backup %q: %w", change.Backup, err)
		}
	}
	return change, saveSettings(path, settings)
}

func encodeSettings(settings map[string]any) ([]byte, error) {
	data, err := json.MarshalIndent(settings, "", " ")
	if err != nil {
		return nil, fmt.Errorf("install-guard: marshal settings: %w", err)
	}
	return append(data, '\n'), nil
}

// hasCurrentGuard reports whether settings run the Go guard.
func hasCurrentGuard(v any) bool {
	switch t := v.(type) {
	case string:
		return isCurrentGuard(t)
	case []any:
		for _, e := range t {
			if hasCurrentGuard(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range t {
			if hasCurrentGuard(e) {
				return true
			}
		}
	}
	return false
}

// uninstallClaudeCode removes the guard entries, the current Go guard and the
// script guards of earlier versions, from every settings file.
func uninstallClaudeCode(opts InstallOpts) (string, bool, error) {
	paths, err := ClaudeSettingsPaths(opts)
	if err != nil {
		return "", false, err
	}
	removed := false
	for _, path := range paths {
		settings, err := loadSettings(path)
		if err != nil {
			return "", false, err
		}
		_, did := pruneHooks(settings, func(cmd string) bool { return isCurrentGuard(cmd) || isLegacyGuard(cmd) })
		if !did {
			continue
		}
		if err := saveSettings(path, settings); err != nil {
			return "", false, err
		}
		removed = true
	}
	return paths[0], removed, nil
}
