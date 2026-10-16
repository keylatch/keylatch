package harness

import (
	"os"
	"path/filepath"
	"strings"
)

// Env is what path resolution reads from the machine.
type Env struct {
	// Home is the user's home directory.
	Home string
	// Getenv reads an environment variable; os.Getenv when nil.
	Getenv func(string) string
	// Project is the project root for project-level files; empty for the
	// user-level files.
	Project string
}

// SystemEnv reads the home directory and environment of this process.
func SystemEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	return Env{Home: home}, nil
}

func (e Env) get(name string) string {
	if e.Getenv != nil {
		return e.Getenv(name)
	}
	return os.Getenv(name)
}

// Layout is a harness's files on one machine.
type Layout struct {
	// Dir is the configuration directory (the project root for project scope).
	Dir string
	// Hook, MCP and Rules are absolute paths; empty when the harness has no such
	// file at that scope.
	Hook  string
	MCP   string
	Rules string
}

// Dir resolves the user-level configuration directory.
func (d Descriptor) Dir(e Env) string {
	c := d.Config
	if c.Env != "" {
		if v := strings.TrimSpace(e.get(c.Env)); v != "" {
			return filepath.Clean(v)
		}
	}
	home := e.Home
	if c.EnvHome != "" {
		if v := strings.TrimSpace(e.get(c.EnvHome)); v != "" {
			home = v
		}
	}
	if len(c.XDG) > 0 {
		base := strings.TrimSpace(e.get("XDG_CONFIG_HOME"))
		if base == "" {
			base = filepath.Join(home, ".config")
		}
		return filepath.Join(append([]string{base}, c.XDG...)...)
	}
	return filepath.Join(append([]string{home}, c.Rel...)...)
}

// Layout resolves the harness's files for e: the user-level files, or the
// project-level ones when e.Project is set.
func (d Descriptor) Layout(e Env) Layout {
	if e.Project != "" {
		l := Layout{Dir: e.Project}
		if d.Hook != nil && d.Hook.ProjectFile != "" {
			l.Hook = filepath.Join(e.Project, filepath.FromSlash(d.Hook.ProjectFile))
		}
		if d.Rules != nil && d.Rules.ProjectFile != "" {
			l.Rules = filepath.Join(e.Project, filepath.FromSlash(d.Rules.ProjectFile))
		}
		return l
	}
	dir := d.Dir(e)
	l := Layout{Dir: dir}
	if d.Hook != nil {
		l.Hook = filepath.Join(dir, filepath.FromSlash(d.Hook.File))
	}
	if d.MCP != nil {
		l.MCP = filepath.Join(dir, filepath.FromSlash(d.MCP.File))
		if d.MCP.HomeFile != "" && !d.dirOverridden(e) {
			l.MCP = filepath.Join(e.Home, filepath.FromSlash(d.MCP.HomeFile))
		}
	}
	if d.Rules != nil && d.Rules.File != "" {
		l.Rules = filepath.Join(dir, filepath.FromSlash(d.Rules.File))
	}
	return l
}

func (d Descriptor) dirOverridden(e Env) bool {
	return d.Config.Env != "" && strings.TrimSpace(e.get(d.Config.Env)) != ""
}

// HookDisplay names the user-level hook file the way a person would write it
// ("~/.cursor/hooks.json"), for help text and messages.
func (d Descriptor) HookDisplay() string {
	if d.Hook == nil {
		return ""
	}
	if base := d.relDir(); base != "" {
		return "~/" + base + "/" + d.Hook.File
	}
	return d.Hook.File
}

// ConfigDirNames lists the base names of every harness configuration
// directory under the home directory, for code that must keep an untrusted
// process away from them.
func ConfigDirNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range descriptors {
		name := d.relDir()
		if name == "" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// ProtectedFiles lists, as slash-separated path suffixes, every file a harness
// reads hooks or MCP servers from, its project-level hook file and the extra
// files the descriptor protects. A trailing slash marks a directory. Code that
// keeps an agent from switching its own guard off matches against them.
func ProtectedFiles() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, d := range descriptors {
		base := d.relDir()
		join := func(file string) string {
			if base == "" || file == "" {
				return ""
			}
			return base + "/" + file
		}
		if d.Hook != nil {
			add(join(d.Hook.File))
			add(d.Hook.ProjectFile)
		}
		if d.MCP != nil {
			add(join(d.MCP.File))
			add(d.MCP.HomeFile)
		}
		for _, p := range d.Protected {
			add(p)
		}
	}
	return out
}

// relDir is the configuration directory relative to the home directory, in its
// default location.
func (d Descriptor) relDir() string {
	switch {
	case len(d.Config.XDG) > 0:
		return strings.Join(append([]string{".config"}, d.Config.XDG...), "/")
	case len(d.Config.Rel) > 0:
		return strings.Join(d.Config.Rel, "/")
	}
	return ""
}
