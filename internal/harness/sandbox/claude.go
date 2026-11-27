package sandbox

import (
	"fmt"
	"runtime"
	"slices"
)

// HardenClaudeSettings merges what Keylatch needs from Claude Code's sandbox
// into a settings document and reports whether it changed:
//
//   - every keylatch entry leaves sandbox.excludedCommands, because an excluded
//     `keylatch run` starts its child outside the sandbox;
//   - sandbox.allowUnsandboxedCommands is false, so a command the sandbox
//     refuses cannot be retried outside it;
//   - the daemon sockets join sandbox.network.allowUnixSockets and local
//     binding is allowed, which the in-sandbox forwarder to the daemon needs.
//
// Everything else in the document is left as the user wrote it.
func HardenClaudeSettings(settings map[string]any, sockets []string, denyRead ...string) (bool, error) {
	box, err := object(settings, "sandbox")
	if err != nil {
		return false, err
	}
	changed, err := dropKeylatchExclusions(box)
	if err != nil {
		return false, err
	}
	if v, ok := box["allowUnsandboxedCommands"]; !ok || v != false {
		box["allowUnsandboxedCommands"], changed = false, true
	}
	if box["enabled"] != true {
		box["enabled"], changed = true, true
	}
	if len(denyRead) > 0 {
		filesystem, err := object(box, "filesystem")
		if err != nil {
			return false, err
		}
		if filesystem["disabled"] != false {
			filesystem["disabled"], changed = false, true
		}
		denied, err := stringList(filesystem, "denyRead")
		if err != nil {
			return false, err
		}
		for _, path := range denyRead {
			if !slices.Contains(denied, path) {
				denied, changed = append(denied, path), true
			}
		}
		filesystem["denyRead"] = toAny(denied)
	}
	if len(sockets) == 0 {
		return changed, nil
	}
	network, err := object(box, "network")
	if err != nil {
		return false, err
	}
	if v, ok := network["allowLocalBinding"]; !ok || v != true {
		network["allowLocalBinding"], changed = true, true
	}
	// Linux seccomp cannot allow individual Unix socket paths.
	if runtime.GOOS == "linux" && network["allowAllUnixSockets"] != true {
		network["allowAllUnixSockets"], changed = true, true
	}
	allowed, err := stringList(network, "allowUnixSockets")
	if err != nil {
		return false, err
	}
	for _, s := range sockets {
		if !slices.Contains(allowed, s) {
			allowed, changed = append(allowed, s), true
		}
	}
	network["allowUnixSockets"] = toAny(allowed)
	return changed, nil
}

// RemoveClaudeSockets takes the sockets HardenClaudeSettings allowed out of a
// settings document and reports whether it changed. The other hardening stays:
// removing it would loosen the user's sandbox.
func RemoveClaudeSockets(settings map[string]any, sockets []string) (bool, error) {
	box, ok := settings["sandbox"].(map[string]any)
	if !ok {
		return false, nil
	}
	network, ok := box["network"].(map[string]any)
	if !ok {
		return false, nil
	}
	allowed, err := stringList(network, "allowUnixSockets")
	if err != nil {
		return false, err
	}
	kept := slices.DeleteFunc(slices.Clone(allowed), func(s string) bool { return slices.Contains(sockets, s) })
	if len(kept) == len(allowed) {
		return false, nil
	}
	if runtime.GOOS == "linux" {
		network["allowAllUnixSockets"] = false
	}
	if len(kept) == 0 {
		delete(network, "allowUnixSockets")
	} else {
		network["allowUnixSockets"] = toAny(kept)
	}
	return true, nil
}

func dropKeylatchExclusions(box map[string]any) (bool, error) {
	excluded, err := stringList(box, "excludedCommands")
	if err != nil {
		return false, err
	}
	kept := slices.DeleteFunc(slices.Clone(excluded), func(pattern string) bool {
		matches, _ := MatchKeylatch(pattern)
		return matches
	})
	if len(kept) == len(excluded) {
		return false, nil
	}
	if len(kept) == 0 {
		delete(box, "excludedCommands")
	} else {
		box["excludedCommands"] = toAny(kept)
	}
	return true, nil
}

// object returns the object under key, creating it when missing.
func object(parent map[string]any, key string) (map[string]any, error) {
	v, ok := parent[key]
	if !ok {
		child := map[string]any{}
		parent[key] = child
		return child, nil
	}
	child, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("existing %q value is not an object", key)
	}
	return child, nil
}

// stringList reads an array of strings; a missing key is an empty list.
func stringList(parent map[string]any, key string) ([]string, error) {
	v, ok := parent[key]
	if !ok {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("existing %q value is not an array", key)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("existing %q array holds a value that is not a string", key)
		}
		out = append(out, s)
	}
	return out, nil
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
