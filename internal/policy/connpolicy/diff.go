package connpolicy

import (
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/callerkind"
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
	if rule, ok := d.Callers[callerkind.Machine]; ok {
		if rule.Allow {
			parts = append(parts, "machine=allow"+ruleDetail(rule))
		} else {
			parts = append(parts, "machine=deny")
		}
	}
	if len(d.Capabilities) > 0 {
		parts = append(parts, "capabilities="+strings.Join(d.Capabilities, ","))
	}
	if d.MaxTTL != "" {
		parts = append(parts, "max_ttl="+d.MaxTTL)
	}
	if len(d.Hosts) > 0 {
		parts = append(parts, "hosts="+strings.Join(d.Hosts, ","))
	}
	if d.Egress != nil && len(d.Egress.Allow) > 0 {
		parts = append(parts, "egress="+strings.Join(d.Egress.Allow, ","))
	}
	if d.FS != nil {
		for _, f := range []struct {
			name  string
			paths []string
		}{{"fs.read", d.FS.Read}, {"fs.write", d.FS.Write}, {"fs.deny", d.FS.Deny}} {
			if len(f.paths) > 0 {
				parts = append(parts, f.name+"="+strings.Join(f.paths, ","))
			}
		}
	}
	for _, c := range d.Commands {
		parts = append(parts, "command="+strings.Join(c.Match, " ")+commandDetail(c))
	}
	if h := d.Host; h != nil {
		parts = append(parts, fmt.Sprintf("host=%s(egress:%d write:%d deny:%d)", h.Source, len(h.EgressAllow), len(h.FSWrite), len(h.FSDeny)))
	}
	return strings.Join(parts, " ")
}

func commandDetail(c CommandRule) string {
	var parts []string
	if len(c.Tiers) > 0 {
		parts = append(parts, "tiers="+strings.Join(c.Tiers, ","))
	}
	if c.Approval != "" {
		parts = append(parts, "approval="+c.Approval)
	}
	if c.ExeSHA256 != "" {
		parts = append(parts, "pinned")
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, " ") + "]"
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
	if len(r.Tiers) > 0 {
		parts = append(parts, "tiers="+strings.Join(r.Tiers, ","))
	}
	if r.Approval != "" {
		parts = append(parts, "approval="+r.Approval)
	}
	if r.TTL != "" {
		parts = append(parts, "ttl="+r.TTL)
	}
	if r.MaxRequests > 0 {
		parts = append(parts, fmt.Sprintf("max_requests=%d", r.MaxRequests))
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
	seen := make(map[string]bool)
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
