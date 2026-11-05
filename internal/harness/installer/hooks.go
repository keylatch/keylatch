package installer

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/keylatch/keylatch/internal/harness/merge"
)

// GuardMarker is the tail of every hook command Keylatch installs. It
// identifies the Keylatch entry among the user's own hooks whatever binary
// path stands in front of it.
func GuardMarker(d Descriptor) string { return " guard hook --harness " + d.Adapter }

// GuardCommand is the hook command line: the absolute Keylatch binary, quoted
// so a path with a space survives the harness's shell, followed by the marker.
// On Windows the path uses forward slashes, which the shells harnesses start
// accept and which survive their quoting.
func GuardCommand(d Descriptor, keylatchPath string) string {
	if runtime.GOOS == "windows" {
		keylatchPath = strings.ReplaceAll(keylatchPath, `\`, "/")
	}
	return quoteShell(keylatchPath) + GuardMarker(d)
}

func quoteShell(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(s) + `"`
}

// legacyGuardRe matches the shell scripts earlier releases installed.
var legacyGuardRe = regexp.MustCompile(`block-keylatch-exfiltration\.sh|\.keylatch[/\\](hooks|guards)[/\\][a-z-]+-guard\.sh`)

func isLegacyGuard(command string) bool { return legacyGuardRe.MatchString(command) }

// hookEntry is one registration: the event it goes under and how the entry
// looks there.
type hookEntry struct {
	event string
	build func(command string) *merge.Object
}

// hookPlan is how a harness's JSON hook file is laid out.
type hookPlan struct {
	// container is the top-level key that holds the events.
	container string
	// prepare sets top-level keys the file needs besides the events; it runs
	// before the container is created so they come first in a new file.
	prepare func(root *merge.Object)
	// initContainer sets keys the container itself needs.
	initContainer func(container *merge.Object)
	entries       []hookEntry
}

func obj(pairs ...any) *merge.Object {
	o := merge.NewObject()
	for i := 0; i+1 < len(pairs); i += 2 {
		o.Set(pairs[i].(string), pairs[i+1])
	}
	return o
}

// commandHook is the leaf most harnesses take: a command and a timeout.
func commandHook(command string, extra ...any) *merge.Object {
	return obj(append([]any{"type", "command", "command", command}, extra...)...)
}

// installHooks registers the guard command in a JSON hook file and reports
// whether the document changed. It keeps the user's other hooks, replaces
// entries earlier releases wrote, and with upgrade rewrites the command of an
// installed entry in place.
func installHooks(root *merge.Object, plan hookPlan, marker, command string, upgrade bool) error {
	if plan.prepare != nil {
		plan.prepare(root)
	}
	migrateLegacyArray(root, plan.container)
	container, err := root.Child(plan.container)
	if err != nil {
		return err
	}
	if plan.initContainer != nil {
		plan.initContainer(container)
	}
	for _, e := range plan.entries {
		arr, err := container.List(e.event)
		if err != nil {
			return err
		}
		arr, _ = pruneArray(arr, isLegacyGuard)
		have := false
		for i, el := range arr {
			o, ok := el.(*merge.Object)
			if !ok {
				continue
			}
			switch {
			case ownedLeaf(o, marker), ownedGroup(o, marker):
				have = true
				if upgrade {
					arr[i] = e.build(command)
				}
			default:
				walkLeaves([]any{o}, func(leaf *merge.Object, key string) {
					if s, _ := leaf.Get(key); strings.HasSuffix(fmt.Sprint(s), marker) {
						have = true
						if upgrade {
							leaf.Set(key, command)
						}
					}
				})
			}
		}
		if !have {
			arr = append(arr, e.build(command))
		}
		container.Set(e.event, arr)
	}
	return nil
}

// ownedLeaf is an entry that is just a Keylatch command.
func ownedLeaf(o *merge.Object, marker string) bool {
	for _, k := range commandKeys {
		if v, ok := o.Get(k); ok {
			if s, isStr := v.(string); isStr && strings.HasSuffix(s, marker) {
				return true
			}
		}
	}
	return false
}

// ownedGroup is a matcher group whose only hook is a Keylatch command, so the
// whole group can be rewritten without touching anything of the user's.
func ownedGroup(o *merge.Object, marker string) bool {
	inner, err := o.List("hooks")
	if err != nil || len(inner) != 1 {
		return false
	}
	leaf, ok := inner[0].(*merge.Object)
	return ok && ownedLeaf(leaf, marker)
}

// migrateLegacyArray converts the array-form "hooks" value older releases wrote
// (each entry naming its "event") into the object form the harnesses read.
// Entries without an event are kept under "hooksLegacy" rather than dropped.
func migrateLegacyArray(root *merge.Object, container string) {
	legacy, err := root.List(container)
	if err != nil || legacy == nil {
		return
	}
	obj := merge.NewObject()
	var leftovers []any
	for _, raw := range legacy {
		entry, ok := raw.(*merge.Object)
		if !ok {
			leftovers = append(leftovers, raw)
			continue
		}
		ev, _ := entry.Get("event")
		event, _ := ev.(string)
		if event == "" {
			leftovers = append(leftovers, raw)
			continue
		}
		entry.Delete("event")
		arr, _ := obj.List(event)
		obj.Set(event, append(arr, entry))
	}
	if len(leftovers) > 0 {
		root.Set(container+"Legacy", leftovers)
	}
	root.Set(container, obj)
}

// removeHooks deletes every Keylatch entry, current or legacy, from a JSON
// hook file and reports whether any existed.
func removeHooks(root *merge.Object, plan hookPlan, marker string) bool {
	removed := false
	if v, ok := root.Get(plan.container); ok {
		if container, ok := v.(*merge.Object); ok {
			for _, e := range plan.entries {
				arr, err := container.List(e.event)
				if err != nil || arr == nil {
					continue
				}
				pruned, changed := pruneArray(arr, func(s string) bool { return isLegacyGuard(s) || strings.HasSuffix(s, marker) })
				if !changed {
					continue
				}
				removed = true
				if len(pruned) == 0 {
					container.Delete(e.event)
				} else {
					container.Set(e.event, pruned)
				}
			}
			if len(container.Keys()) == 0 || onlyKeys(container, "enabled") {
				root.Delete(plan.container)
			}
		}
	}
	return removed
}

// removeLegacyHooks drops the entries earlier releases wrote under any event of
// the container, and the container when that leaves it empty.
func removeLegacyHooks(root *merge.Object, container string) {
	v, ok := root.Get(container)
	if !ok {
		return
	}
	c, ok := v.(*merge.Object)
	if !ok {
		return
	}
	for _, event := range c.Keys() {
		arr, err := c.List(event)
		if err != nil || arr == nil {
			continue
		}
		pruned, changed := pruneArray(arr, isLegacyGuard)
		switch {
		case !changed:
		case len(pruned) == 0:
			c.Delete(event)
		default:
			c.Set(event, pruned)
		}
	}
	if len(c.Keys()) == 0 {
		root.Delete(container)
	}
}

func onlyKeys(o *merge.Object, keys ...string) bool {
	for _, k := range o.Keys() {
		found := false
		for _, want := range keys {
			found = found || k == want
		}
		if !found {
			return false
		}
	}
	return true
}

var commandKeys = []string{"command", "bash"}

// walkLeaves calls fn for every object in arr, at any depth through "hooks"
// arrays, that carries a command string, with the key it is under.
func walkLeaves(arr []any, fn func(leaf *merge.Object, key string)) {
	for _, el := range arr {
		o, ok := el.(*merge.Object)
		if !ok {
			continue
		}
		for _, k := range commandKeys {
			if v, ok := o.Get(k); ok {
				if _, isStr := v.(string); isStr {
					fn(o, k)
				}
			}
		}
		if inner, err := o.List("hooks"); err == nil {
			walkLeaves(inner, fn)
		}
	}
}

// pruneArray drops the leaves whose command satisfies stale and the groups that
// held only such leaves, and reports whether anything went.
func pruneArray(arr []any, stale func(string) bool) ([]any, bool) {
	out := make([]any, 0, len(arr))
	changed := false
	for _, el := range arr {
		o, ok := el.(*merge.Object)
		if !ok {
			out = append(out, el)
			continue
		}
		if leafStale(o, stale) {
			changed = true
			continue
		}
		if inner, err := o.List("hooks"); err == nil && inner != nil {
			pruned, c := pruneArray(inner, stale)
			if c {
				changed = true
				if len(pruned) == 0 {
					continue
				}
				o.Set("hooks", pruned)
			}
		}
		out = append(out, o)
	}
	return out, changed
}

func leafStale(o *merge.Object, stale func(string) bool) bool {
	for _, k := range commandKeys {
		if v, ok := o.Get(k); ok {
			if s, isStr := v.(string); isStr && stale(s) {
				return true
			}
		}
	}
	return false
}

// hasGuard reports whether the hook file registers a Keylatch command.
func hasGuard(root *merge.Object, plan hookPlan, marker string) bool {
	v, ok := root.Get(plan.container)
	if !ok {
		return false
	}
	container, ok := v.(*merge.Object)
	if !ok {
		return false
	}
	found := false
	for _, e := range plan.entries {
		arr, err := container.List(e.event)
		if err != nil {
			continue
		}
		walkLeaves(arr, func(leaf *merge.Object, key string) {
			s, _ := leaf.Get(key)
			if str, _ := s.(string); strings.HasSuffix(str, marker) {
				found = true
			}
		})
	}
	return found
}
