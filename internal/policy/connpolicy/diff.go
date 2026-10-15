package connpolicy

import (
	"fmt"
	"strings"
)

// Describe renders what a document allows on one line, for diffs and the
// summary a human approves.
func Describe(d Document) string {
	parts := make([]string, 0, len(Kinds)+2)
	for _, k := range Kinds {
		rule, ok := d.Callers[k]
		switch {
		case !ok || !rule.Allow:
			parts = append(parts, fmt.Sprintf("%s=deny", k))
		default:
			parts = append(parts, fmt.Sprintf("%s=allow%s", k, ruleDetail(rule)))
		}
	}
	if len(d.Capabilities) > 0 {
		parts = append(parts, "capabilities="+strings.Join(d.Capabilities, ","))
	}
	if d.MaxTTL != "" {
		parts = append(parts, "max_ttl="+d.MaxTTL)
	}
	return strings.Join(parts, " ")
}

func ruleDetail(r CallerRule) string {
	var parts []string
	if len(r.Runtimes) > 0 {
		parts = append(parts, "runtimes="+strings.Join(r.Runtimes, ","))
	}
	if len(r.Exe) > 0 {
		parts = append(parts, "exe="+strings.Join(r.Exe, ","))
	}
	if len(r.Units) > 0 {
		parts = append(parts, "units="+strings.Join(r.Units, ","))
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// Diff lists the changes that turn before into after, one line per connection,
// in connection order. Equal sets give no lines.
func Diff(before, after map[string]Document) []string {
	var lines []string
	seen := make(map[string]bool, len(before)+len(after))
	for _, c := range append(Connections(before), Connections(after)...) {
		if seen[c] {
			continue
		}
		seen[c] = true
		b, hadB := before[c]
		a, hasA := after[c]
		switch {
		case !hadB:
			lines = append(lines, fmt.Sprintf("+ %s: %s", c, Describe(a)))
		case !hasA:
			lines = append(lines, fmt.Sprintf("- %s: %s", c, Describe(b)))
		default:
			if db, da := Describe(b), Describe(a); db != da {
				lines = append(lines, fmt.Sprintf("~ %s: %s -> %s", c, db, da))
			}
		}
	}
	return lines
}
