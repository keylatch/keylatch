package sync

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Summarize describes what a manifest writes, by target: where each target
// is, which connection each name comes from, and the hosts a verification
// request would reach, never values. only limits it to one variable and target
// to one target. It is what the human reads when asked to approve an apply or
// a rotation, so it is built from the manifest itself and names everything
// that decides where a secret goes.
func Summarize(raw []byte, only, target string) string {
	m, err := Parse(raw, nil)
	if err != nil {
		return "a manifest that does not validate"
	}
	names := map[string][]string{}
	hosts := map[string]bool{}
	for _, v := range m.Vars {
		if only != "" && v.Name != only {
			continue
		}
		used := false
		for tn := range v.To {
			if target == "" || tn == target {
				names[tn] = append(names[tn], fmt.Sprintf("%s<-%s", v.Name, sourceName(v.From)))
				used = true
			}
		}
		if used && v.Verify != nil {
			hosts[VerifyHost(v.Verify.URL)] = true
		}
	}
	targets := make([]string, 0, len(names))
	for tn := range names {
		targets = append(targets, tn)
	}
	sort.Strings(targets)
	parts := make([]string, 0, len(targets)+1)
	for _, tn := range targets {
		sort.Strings(names[tn])
		parts = append(parts, fmt.Sprintf("%s (%s): %d name(s) %s", tn, describeTarget(m.Targets[tn]), len(names[tn]), strings.Join(names[tn], ", ")))
	}
	if len(parts) == 0 {
		return "no targets"
	}
	if len(hosts) > 0 {
		hs := make([]string, 0, len(hosts))
		for h := range hosts {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		parts = append(parts, "verified against "+strings.Join(hs, ", "))
	}
	return strings.Join(parts, "; ")
}

func sourceName(s Source) string {
	if s.Field == "" {
		return s.Connection
	}
	return s.Connection + "." + s.Field
}

// describeTarget lists what places a target: its type and every field that
// says where it writes or whose credential it uses.
func describeTarget(t Target) string {
	parts := []string{t.Type}
	for _, kv := range [][2]string{{"repo", t.Repo}, {"project", t.Project}, {"team", t.Team}, {"link", t.Link}, {"path", t.Path}, {"credential", t.Credential}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+" "+kv[1])
		}
	}
	return strings.Join(parts, ", ")
}

// VerifyHost is the host (with any port) a verification URL reaches, or the
// URL itself when it does not parse, so the summary never hides it.
func VerifyHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return strings.ToLower(u.Host)
}
