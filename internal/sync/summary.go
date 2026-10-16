package sync

import (
	"fmt"
	"sort"
	"strings"
)

// Summarize describes what a manifest writes, by target: counts and names,
// never values. only limits it to one variable and target to one target. It
// is what the human reads when asked to approve an apply or a rotation, so it
// is built from the manifest itself.
func Summarize(raw []byte, only, target string) string {
	m, err := Parse(raw, nil)
	if err != nil {
		return "a manifest that does not validate"
	}
	names := map[string][]string{}
	for _, v := range m.Vars {
		if only != "" && v.Name != only {
			continue
		}
		for tn := range v.To {
			if target == "" || tn == target {
				names[tn] = append(names[tn], v.Name)
			}
		}
	}
	targets := make([]string, 0, len(names))
	for tn := range names {
		targets = append(targets, tn)
	}
	sort.Strings(targets)
	parts := make([]string, 0, len(targets))
	for _, tn := range targets {
		sort.Strings(names[tn])
		parts = append(parts, fmt.Sprintf("%s (%s): %d name(s) %s", tn, m.Targets[tn].Type, len(names[tn]), strings.Join(names[tn], ", ")))
	}
	if len(parts) == 0 {
		return "no targets"
	}
	return strings.Join(parts, "; ")
}
