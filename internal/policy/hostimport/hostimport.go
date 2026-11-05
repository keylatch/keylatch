// Package hostimport reads the sandbox settings of an agent harness and turns
// them into the limits a Keylatch policy keeps: the domains a contained run may
// reach, the paths it may write and the paths it may never touch. The import is
// one-way and only narrows; it also finds excluded commands that would let an
// agent step outside its sandbox into Keylatch.
package hostimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/registry"
)

// Hosts the importer understands.
const (
	ClaudeCode = "claude-code"
	Codex      = "codex"
	Gemini     = "gemini"
)

// Hosts lists them in a stable order.
var Hosts = []string{ClaudeCode, Codex, Gemini}

// Bounds is what an import found.
type Bounds struct {
	connpolicy.HostBounds
	// Excluded are the commands the host runs outside its sandbox.
	Excluded []string
	// Warnings name entries that were skipped and why.
	Warnings []string
	// Files are the settings that were read.
	Files []string
}

// DefaultFiles returns the settings files of a host that exist, user level
// first, for a project at dir.
func DefaultFiles(host, home, dir string) []string {
	user := harness.Env{Home: home, Getenv: func(string) string { return "" }}
	project := harness.Env{Project: dir}
	var candidates []string
	switch host {
	case ClaudeCode:
		d, _ := harness.Lookup("claude-code")
		projectSettings := d.Layout(project).Hook
		candidates = []string{
			d.Layout(user).Hook,
			projectSettings,
			filepath.Join(filepath.Dir(projectSettings), "settings.local.json"),
		}
	case Codex:
		d, _ := harness.Lookup("codex")
		candidates = []string{d.Layout(user).MCP}
	case Gemini:
		d, _ := harness.Lookup("gemini-cli")
		candidates = []string{d.Layout(user).Hook, d.Layout(project).Hook}
	}
	var out []string
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.Mode().IsRegular() {
			out = append(out, c)
		}
	}
	return out
}

// Load reads the settings files of host and merges their limits: lists add up,
// and a limit set by any file applies.
func Load(host string, files []string) (Bounds, error) {
	if !slices.Contains(Hosts, host) {
		return Bounds{}, fmt.Errorf("unknown host %q; use %s", host, strings.Join(Hosts, ", "))
	}
	if len(files) == 0 {
		return Bounds{}, fmt.Errorf("no %s settings found; name them with --settings", host)
	}
	b := Bounds{HostBounds: connpolicy.HostBounds{Source: host}}
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // G304: the caller names the settings file
		if err != nil {
			return Bounds{}, err
		}
		b.Files = append(b.Files, f)
		var s settings
		switch host {
		case ClaudeCode:
			s, err = claudeSettings(data)
		case Codex:
			s, err = codexSettings(data)
		default:
			s, err = geminiSettings(data)
		}
		if err != nil {
			return Bounds{}, fmt.Errorf("%s: %w", f, err)
		}
		b.merge(s)
	}
	b.finish()
	return b, nil
}

// settings is one file's contribution before it is checked.
type settings struct {
	domains        []string
	domainsSet     bool
	allowWrite     []string
	writeSet       bool
	deny           []string
	excluded       []string
	writeProject   bool
	networkAllowed *bool
}

func (b *Bounds) merge(s settings) {
	if s.domainsSet {
		b.EgressRestricted = true
		for _, d := range s.domains {
			if err := registry.ValidateHostPattern(d); err != nil {
				b.Warnings = append(b.Warnings, fmt.Sprintf("allowed domain %q skipped: %v", d, err))
				continue
			}
			b.EgressAllow = append(b.EgressAllow, d)
		}
	}
	if s.networkAllowed != nil && !*s.networkAllowed {
		// The host allows no network at all.
		b.EgressRestricted = true
	}
	if s.writeSet {
		b.WriteRestricted = true
		if s.writeProject {
			b.FSWrite = append(b.FSWrite, "${project}")
		}
		for _, p := range s.allowWrite {
			if n, ok := normalizePath(p); ok {
				b.FSWrite = append(b.FSWrite, n)
			} else {
				b.Warnings = append(b.Warnings, fmt.Sprintf("writable path %q skipped: not absolute, ~/ or ./ relative", p))
			}
		}
	}
	for _, p := range s.deny {
		if n, ok := normalizePath(p); ok {
			b.FSDeny = append(b.FSDeny, n)
		} else {
			b.Warnings = append(b.Warnings, fmt.Sprintf("denied path %q skipped: not absolute, ~/ or ./ relative", p))
		}
	}
	b.Excluded = append(b.Excluded, s.excluded...)
}

func (b *Bounds) finish() {
	for _, l := range []*[]string{&b.EgressAllow, &b.FSWrite, &b.FSDeny, &b.Excluded} {
		slices.Sort(*l)
		*l = slices.Compact(*l)
	}
}

// normalizePath turns a host's path pattern into a policy path: a trailing glob
// is dropped (the policy matches whole directories), ./x becomes ${project}/x.
func normalizePath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	for _, suffix := range []string{"/**", "/*", "**", "*"} {
		p = strings.TrimSuffix(p, suffix)
	}
	switch {
	case p == "." || p == "./":
		return "${project}", true
	case strings.HasPrefix(p, "./"):
		return "${project}/" + strings.TrimPrefix(path.Clean(p), "./"), true
	case strings.HasPrefix(p, "//"):
		return path.Clean(p[1:]), true // Claude Code writes a rooted path as //path
	case strings.HasPrefix(p, "/"), p == "~", strings.HasPrefix(p, "~/"):
		if strings.Contains(p, "..") || strings.ContainsAny(p, "*?[") {
			return "", false
		}
		return path.Clean(p), true
	}
	return "", false
}

func claudeSettings(data []byte) (settings, error) {
	var raw struct {
		Sandbox struct {
			ExcludedCommands []string `json:"excludedCommands"`
			Network          *struct {
				AllowedDomains *[]string `json:"allowedDomains"`
			} `json:"network"`
			Filesystem *struct {
				AllowWrite []string `json:"allowWrite"`
				DenyWrite  []string `json:"denyWrite"`
				DenyRead   []string `json:"denyRead"`
			} `json:"filesystem"`
		} `json:"sandbox"`
		Permissions struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return settings{}, fmt.Errorf("not valid JSON: %w", err)
	}
	s := settings{excluded: raw.Sandbox.ExcludedCommands}
	if n := raw.Sandbox.Network; n != nil && n.AllowedDomains != nil {
		s.domains, s.domainsSet = *n.AllowedDomains, true
		if slices.Contains(s.domains, "*") {
			s.domains, s.domainsSet = nil, false
		}
	}
	if fs := raw.Sandbox.Filesystem; fs != nil {
		if fs.AllowWrite != nil {
			s.allowWrite, s.writeSet, s.writeProject = fs.AllowWrite, true, true
		}
		s.deny = append(s.deny, fs.DenyRead...)
		s.deny = append(s.deny, fs.DenyWrite...)
	}
	for _, rule := range raw.Permissions.Deny {
		if inner, ok := toolRule(rule); ok {
			s.deny = append(s.deny, inner)
		}
	}
	return s, nil
}

// toolRule extracts the path of a Read(...) or Edit(...) deny rule.
func toolRule(rule string) (string, bool) {
	for _, tool := range []string{"Read", "Edit", "Write", "MultiEdit"} {
		if inner, ok := strings.CutPrefix(rule, tool+"("); ok {
			return strings.TrimSuffix(inner, ")"), true
		}
	}
	return "", false
}

func geminiSettings(data []byte) (settings, error) {
	var raw struct {
		ExcludedCommands []string `json:"excludedCommands"`
		Sandbox          any      `json:"sandbox"`
		Tools            struct {
			Sandbox any `json:"sandbox"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return settings{}, fmt.Errorf("not valid JSON: %w", err)
	}
	s := settings{excluded: raw.ExcludedCommands}
	for _, sb := range []any{raw.Sandbox, raw.Tools.Sandbox} {
		m, ok := sb.(map[string]any)
		if !ok {
			continue
		}
		if net, ok := m["network"].(map[string]any); ok {
			if list, ok := stringList(net["allowedDomains"]); ok {
				s.domains, s.domainsSet = list, true
			}
		}
		if list, ok := stringList(m["excludedCommands"]); ok {
			s.excluded = append(s.excluded, list...)
		}
	}
	return s, nil
}

func stringList(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if str, ok := e.(string); ok {
			out = append(out, str)
		}
	}
	return out, true
}

func codexSettings(data []byte) (settings, error) {
	root, err := parseTOML(string(data))
	if err != nil {
		return settings{}, err
	}
	s := settings{}
	mode, _ := root["sandbox_mode"].(string)
	ws, _ := root["sandbox_workspace_write"].(map[string]any)
	switch mode {
	case "read-only":
		s.writeSet = true
		no := false
		s.networkAllowed = &no
	case "workspace-write":
		s.writeSet, s.writeProject = true, true
		if roots, ok := stringList(ws["writable_roots"]); ok {
			s.allowWrite = roots
		}
		if net, ok := ws["network_access"].(bool); ok {
			s.networkAllowed = &net
		} else {
			no := false
			s.networkAllowed = &no
		}
	}
	return s, nil
}

// wrappers can start another program: an excluded wrapper lets an agent run
// keylatch outside the sandbox.
var wrappers = []string{
	"sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "env", "xargs", "sudo", "doas", "nohup", "nice", "timeout",
	"time", "command", "exec", "eval", "busybox", "script", "setsid", "stdbuf", "flock", "watch",
	"python", "python3", "node", "perl", "ruby", "deno", "bun", "php", "lua", "awk", "find",
}

// LintExcluded returns the excluded commands that name Keylatch, match
// everything, or can start Keylatch. Each entry is a command pattern such as
// "docker:*" or "keylatch run:*".
func LintExcluded(commands []string) []string {
	var bad []string
	for _, c := range commands {
		word, _, _ := strings.Cut(strings.TrimSpace(c), " ")
		word, _, _ = strings.Cut(word, ":")
		word = strings.ToLower(filepath.Base(strings.TrimSuffix(word, "*")))
		switch {
		case strings.TrimSpace(c) == "", word == "", word == "*", word == ".":
			bad = append(bad, c+" (matches every command)")
		case strings.HasPrefix(word, "keylatch"):
			bad = append(bad, c+" (names Keylatch)")
		case slices.Contains(wrappers, word):
			bad = append(bad, c+" (can start any program, including keylatch)")
		}
	}
	return bad
}

// Diff lists how current differs from the last import: entries added since and
// entries no longer present.
func Diff(last, current connpolicy.HostBounds) []string {
	var out []string
	cmp := func(label string, before, after []string) {
		for _, a := range after {
			if !slices.Contains(before, a) {
				out = append(out, "+ "+label+" "+a)
			}
		}
		for _, b := range before {
			if !slices.Contains(after, b) {
				out = append(out, "- "+label+" "+b)
			}
		}
	}
	cmp("egress", last.EgressAllow, current.EgressAllow)
	cmp("write", last.FSWrite, current.FSWrite)
	cmp("deny", last.FSDeny, current.FSDeny)
	if last.EgressRestricted != current.EgressRestricted {
		out = append(out, fmt.Sprintf("~ egress_restricted %v -> %v", last.EgressRestricted, current.EgressRestricted))
	}
	if last.WriteRestricted != current.WriteRestricted {
		out = append(out, fmt.Sprintf("~ write_restricted %v -> %v", last.WriteRestricted, current.WriteRestricted))
	}
	return out
}

var errTOML = errors.New("unsupported TOML")
