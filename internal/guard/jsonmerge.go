package guard

import (
	"fmt"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
)

// claudeGuardSuffix identifies the Keylatch guard among a user's Claude Code
// hooks whatever the binary path in front of it is.
const claudeGuardSuffix = " guard hook --harness claude-code"

const claudeGuardTimeout = 10

func isCurrentGuard(command string) bool { return strings.HasSuffix(command, claudeGuardSuffix) }

func isLegacyGuard(command string) bool {
	return strings.Contains(command, sharedGuardScript) || legacyGuardRe.MatchString(command)
}

// claudeGuardGroup is the matcher group the installer owns: every tool, the
// guard command, a timeout.
func claudeGuardGroup(command string) map[string]any {
	return map[string]any{"matcher": "*", "hooks": []any{claudeGuardHook(command)}}
}

func claudeGuardHook(command string) map[string]any {
	return map[string]any{"type": "command", "command": command, "timeout": claudeGuardTimeout}
}

// mergeClaudeGuard adds or refreshes the guard in a Claude Code settings map
// and reports whether anything changed. Every other key and hook is kept.
//
//   - A group written by an earlier version (a script path) is replaced where
//     it stood.
//   - A current guard entry is left alone, unless upgrade is set: then its
//     command, matcher and timeout are rewritten in place.
//   - With no guard entry, one group is appended to PreToolUse.
func mergeClaudeGuard(settings map[string]any, command string, upgrade bool) (bool, error) {
	_, changed := migrateLegacyHooks(settings)
	var hooksObj map[string]any
	switch h := settings["hooks"].(type) {
	case nil:
		hooksObj = map[string]any{}
	case map[string]any:
		hooksObj = h
	default:
		return false, fmt.Errorf("existing \"hooks\" value is not an object")
	}
	groups, ok := hooksObj["PreToolUse"].([]any)
	if _, present := hooksObj["PreToolUse"]; present && !ok {
		return false, fmt.Errorf("existing hooks.PreToolUse value is not an array")
	}

	var out []any
	haveCurrent := false
	replaceAt := -1
	for _, raw := range groups {
		group, isMap := raw.(map[string]any)
		inner, _ := group["hooks"].([]any)
		if !isMap || len(inner) == 0 {
			out = append(out, raw)
			continue
		}
		var kept []any
		var owned bool
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			cmd, _ := hm["command"].(string)
			switch {
			case isCurrentGuard(cmd):
				owned = true
				if haveCurrent {
					changed = true // a duplicate guard entry
					continue
				}
				haveCurrent = true
				if upgrade && (cmd != command || !hasTimeout(hm["timeout"]) || group["matcher"] != "*") {
					changed = true
					hm = claudeGuardHook(command)
				}
				kept = append(kept, hm)
			case isLegacyGuard(cmd):
				changed = true
				if replaceAt < 0 {
					replaceAt = len(out)
				}
			default:
				kept = append(kept, h)
			}
		}
		switch {
		case owned && len(kept) == len(inner) && !changed:
			out = append(out, raw)
		case len(kept) == 0:
			// the whole group was legacy guard entries
		default:
			if owned && upgrade && onlyGuard(kept) {
				group["matcher"] = "*"
			}
			group["hooks"] = kept
			out = append(out, group)
		}
	}

	if !haveCurrent {
		changed = true
		g := claudeGuardGroup(command)
		if replaceAt >= 0 && replaceAt <= len(out) {
			out = append(out[:replaceAt], append([]any{g}, out[replaceAt:]...)...)
		} else {
			out = append(out, g)
		}
	}
	if !changed {
		return false, nil
	}
	hooksObj["PreToolUse"] = out
	settings["hooks"] = hooksObj
	return true, nil
}

func hasTimeout(v any) bool {
	switch t := v.(type) {
	case float64:
		return t == claudeGuardTimeout
	case int:
		return t == claudeGuardTimeout
	}
	return false
}

func onlyGuard(hooks []any) bool {
	if len(hooks) != 1 {
		return false
	}
	hm, _ := hooks[0].(map[string]any)
	cmd, _ := hm["command"].(string)
	return isCurrentGuard(cmd)
}

// unifiedDiff renders the change between two versions of a file.
func unifiedDiff(path string, before, after []byte) string {
	d, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(before)),
		B:        difflib.SplitLines(string(after)),
		FromFile: path,
		ToFile:   path + " (after install)",
		Context:  3,
	})
	if err != nil {
		return fmt.Sprintf("cannot render the diff for %s: %v\n", path, err)
	}
	return d
}
