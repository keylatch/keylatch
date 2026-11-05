package installer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/keylatch/keylatch/internal/harness/merge"
)

// ErrNotInstallable is returned for a harness that has no hook mechanism to
// install into.
var ErrNotInstallable = errors.New("harness has nothing Keylatch can install")

// Server is the MCP server entry written into a harness's configuration.
type Server struct {
	// Command is the Keylatch binary.
	Command string
	// Args default to "mcp --stdio".
	Args []string
}

func (s Server) args() []string {
	if len(s.Args) > 0 {
		return s.Args
	}
	return []string{"mcp", "--stdio"}
}

// Parts selects what an install touches. The zero value means all of them.
type Parts struct {
	Guard, MCP, Rules bool
}

// Resolve returns the parts an install touches: all of them when none is named.
func (p Parts) Resolve() Parts {
	if !p.Guard && !p.MCP && !p.Rules {
		return Parts{Guard: true, MCP: true, Rules: true}
	}
	return p
}

// Options controls Install and Uninstall.
type Options struct {
	Env Env
	// Command is the hook command line (GuardCommand); required to install the
	// guard.
	Command string
	// Binary is the absolute Keylatch path the OpenCode plugin runs.
	Binary string
	Server Server
	Parts  Parts
	// Upgrade rewrites an installed entry in place (new binary path).
	Upgrade bool
	// DryRun computes the changes and writes nothing.
	DryRun bool
}

// Result lists what an install or uninstall did.
type Result struct {
	Harness string
	Changes []Change
	// Notes are things the user has to do or should know.
	Notes []string
}

// Changed reports whether any file changed.
func (r Result) Changed() bool {
	for _, c := range r.Changes {
		if c.Changed {
			return true
		}
	}
	return false
}

func num(n int) json.Number { return json.Number(strconv.Itoa(n)) }

func tomlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func tomlStrings(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = tomlString(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// RulesText is the instruction block written into a harness's rules file.
const RulesText = `## Keylatch

Credentials come from Keylatch. Run commands that need one with ` + "`keylatch run <connection> -- <command>`" + ` or the ` + "`keylatch_run`" + ` MCP tool, and list the available connections with ` + "`keylatch list`" + `. Never ask the user for an API key, read credential files or print the environment: Keylatch denies it and the guard hook blocks it.`

func hookPlanFor(d Descriptor) (hookPlan, bool) {
	switch d.ID {
	case "codex":
		return codexPlan(), true
	case "cursor":
		return cursorPlan(), true
	case "gemini-cli":
		return geminiPlan(), true
	case "copilot-cli":
		return copilotPlan(), true
	case "antigravity":
		return antigravityPlan(), true
	case "windsurf":
		return windsurfPlan(), true
	}
	return hookPlan{}, false
}

// Install writes the selected parts into the harness's files: the pre-tool
// hook, the MCP server and the rules block. Claude Code's hook is installed by
// the guard package, which owns its migration of earlier releases; Install
// handles the rest of it.
func Install(d Descriptor, o Options) (Result, error) {
	res := Result{Harness: d.ID}
	if d.Support != SupportGuard {
		return res, fmt.Errorf("%s: %w", d.Name, ErrNotInstallable)
	}
	parts := o.Parts.Resolve()
	layout := d.Layout(o.Env)
	ed := &edits{}

	if parts.Guard && d.ID != "claude-code" {
		if layout.Hook == "" {
			res.Notes = append(res.Notes, d.Name+" has no project-level hook file; install the guard at user level")
		} else if err := planGuardInstall(d, layout, o, ed); err != nil {
			return res, err
		}
	}
	if parts.MCP {
		if layout.MCP == "" {
			res.Notes = append(res.Notes, d.Name+": the MCP server is registered at user level only")
		} else {
			ed.add(layout.MCP, RoleMCP, func(old []byte) ([]byte, error) { return editMCP(d, old, o.Server, o.Upgrade) })
		}
	}
	if parts.Rules {
		if layout.Rules == "" {
			res.Notes = append(res.Notes, d.Name+" reads rules from a project file; run again with --project to add them there")
		} else {
			ed.add(layout.Rules, RoleRules, func(old []byte) ([]byte, error) { return editRules(layout.Rules, old) })
		}
	}
	if d.ID == "codex" && parts.Guard {
		res.Notes = append(res.Notes, "Codex runs a hook only after you review it: open /hooks in Codex and trust the Keylatch hook")
	}
	var err error
	res.Changes, err = ed.apply(merge.Options{DryRun: o.DryRun})
	return res, err
}

// edits collects every change to a file so that two parts sharing one file
// (Gemini CLI keeps hooks and MCP servers in settings.json) are written once and
// the backup holds the file as the user had it.
type edits struct {
	order []string
	fns   map[string][]func([]byte) ([]byte, error)
	roles map[string][]string
}

// Roles a changed file can play.
const (
	RoleHook  = "hook"
	RoleMCP   = "mcp"
	RoleRules = "rules"
)

// Change is one file's outcome and what the file is for.
type Change struct {
	merge.Change
	Roles []string
}

func (e *edits) add(path, role string, fn func([]byte) ([]byte, error)) {
	if e.fns == nil {
		e.fns, e.roles = map[string][]func([]byte) ([]byte, error){}, map[string][]string{}
	}
	if _, ok := e.fns[path]; !ok {
		e.order = append(e.order, path)
	}
	e.fns[path] = append(e.fns[path], fn)
	if !slices.Contains(e.roles[path], role) {
		e.roles[path] = append(e.roles[path], role)
	}
}

func (e *edits) apply(opts merge.Options) ([]Change, error) {
	var out []Change
	for _, path := range e.order {
		fns := e.fns[path]
		c, err := merge.Apply(path, opts, func(old []byte) ([]byte, error) {
			var err error
			for _, fn := range fns {
				if old, err = fn(old); err != nil {
					return nil, err
				}
			}
			return old, nil
		})
		if err != nil {
			return out, err
		}
		out = append(out, Change{Change: c, Roles: e.roles[path]})
	}
	return out, nil
}

func planGuardInstall(d Descriptor, layout Layout, o Options, ed *edits) error {
	if o.Command == "" {
		return errors.New("no guard command given")
	}
	marker := GuardMarker(d)
	if d.Hook.Format == FormatPluginDir {
		ed.add(layout.Hook, RoleHook, func(old []byte) ([]byte, error) {
			if len(old) > 0 && !o.Upgrade {
				return old, nil
			}
			return opencodePluginSource(o.Binary), nil
		})
		return nil
	}
	plan, ok := hookPlanFor(d)
	if !ok {
		return fmt.Errorf("%s: no hook layout", d.Name)
	}
	ed.add(layout.Hook, RoleHook, func(old []byte) ([]byte, error) {
		return merge.EditJSON(old, func(root *merge.Object) error { return installHooks(root, plan, marker, o.Command, o.Upgrade) })
	})
	if d.ID == "cursor" {
		ed.add(filepath.Join(layout.Dir, legacyCursorSettings), RoleHook, func(old []byte) ([]byte, error) {
			if len(old) == 0 {
				return old, nil
			}
			return merge.EditJSON(old, func(root *merge.Object) error {
				removeLegacyHooks(root, plan.container)
				return nil
			})
		})
	}
	return nil
}

func mcpServerObject(d Descriptor, s Server) *merge.Object {
	args := make([]any, 0, len(s.args()))
	for _, a := range s.args() {
		args = append(args, a)
	}
	switch d.ID {
	case "opencode":
		return obj("type", "local", "command", append([]any{s.Command}, args...), "enabled", true)
	case "copilot-cli":
		return obj("type", "local", "command", s.Command, "args", args, "tools", []any{"*"})
	}
	return obj("command", s.Command, "args", args)
}

func editMCP(d Descriptor, old []byte, s Server, upgrade bool) ([]byte, error) {
	if s.Command == "" {
		return nil, errors.New("no MCP server command given")
	}
	if d.MCP.Format == FormatTOML {
		return editTOMLServer(old, s)
	}
	return merge.EditJSON(old, func(root *merge.Object) error {
		servers, err := root.Child(d.MCP.Key)
		if err != nil {
			return err
		}
		if _, exists := servers.Get("keylatch"); exists && !upgrade {
			return nil
		}
		servers.Set("keylatch", mcpServerObject(d, s))
		return nil
	})
}

// editTOMLServer writes the Codex server table. The block is Keylatch's own and
// rewritten in place; a table the user defined by hand outside it is an error,
// not something to overwrite.
func editTOMLServer(old []byte, s Server) ([]byte, error) {
	return merge.TOMLBlock(old, codexServer(s))
}

func editRules(path string, old []byte) ([]byte, error) {
	out, err := merge.MarkdownBlock(old, RulesText)
	if err != nil {
		return nil, err
	}
	if len(old) == 0 && strings.HasSuffix(path, ".mdc") {
		out = append([]byte("---\ndescription: Use Keylatch for credentials\nalwaysApply: true\n---\n\n"), out...)
	}
	return out, nil
}

// Uninstall removes what Install wrote: the hook entries (and any left by
// earlier releases), the MCP server and the rules block. Everything else in
// the files stays. Claude Code's hook is removed by the guard package.
func Uninstall(d Descriptor, o Options) (Result, error) {
	res := Result{Harness: d.ID}
	if d.Support != SupportGuard {
		return res, fmt.Errorf("%s: %w", d.Name, ErrNotInstallable)
	}
	parts := o.Parts.Resolve()
	layout := d.Layout(o.Env)
	ed := &edits{}

	if parts.Guard && d.ID != "claude-code" && layout.Hook != "" {
		if d.Hook.Format == FormatPluginDir {
			if err := removePlugin(layout.Hook, o.DryRun, &res); err != nil {
				return res, err
			}
		} else if plan, ok := hookPlanFor(d); ok {
			marker := GuardMarker(d)
			ed.add(layout.Hook, RoleHook, func(old []byte) ([]byte, error) {
				if len(old) == 0 {
					return old, nil
				}
				return merge.EditJSON(old, func(root *merge.Object) error { removeHooks(root, plan, marker); return nil })
			})
		}
	}
	if parts.MCP && layout.MCP != "" {
		ed.add(layout.MCP, RoleMCP, func(old []byte) ([]byte, error) { return removeMCP(d, old) })
	}
	if parts.Rules && layout.Rules != "" {
		ed.add(layout.Rules, RoleRules, func(old []byte) ([]byte, error) {
			out, _, err := merge.RemoveMarkdownBlock(old)
			return out, err
		})
	}
	changes, err := ed.apply(merge.Options{DryRun: o.DryRun})
	res.Changes = append(res.Changes, changes...)
	if err != nil {
		return res, err
	}
	return res, nil
}

func removePlugin(path string, dryRun bool, res *Result) error {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the harness's own plugin file
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	c := Change{Change: merge.Change{Path: path}, Roles: []string{RoleHook}}
	if bytes.Contains(data, []byte("keylatch guard hook")) {
		c.Changed = true
		if !dryRun {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	res.Changes = append(res.Changes, c)
	return nil
}

func removeMCP(d Descriptor, old []byte) ([]byte, error) {
	if len(old) == 0 {
		return old, nil
	}
	if d.MCP.Format == FormatTOML {
		out, _, err := merge.RemoveTOMLBlock(old)
		return out, err
	}
	return merge.EditJSON(old, func(root *merge.Object) error {
		v, ok := root.Get(d.MCP.Key)
		if !ok {
			return nil
		}
		if servers, ok := v.(*merge.Object); ok {
			servers.Delete("keylatch")
		}
		return nil
	})
}

// Component is one installed piece of a harness integration.
type Component struct {
	Path    string
	Present bool
	// Err is why the file could not be inspected.
	Err error
}

// Status is the state of a harness's integration on this machine.
type Status struct {
	Harness Descriptor
	// Detected is true when the harness's configuration directory exists.
	Detected bool
	Hook     Component
	MCP      Component
	Rules    Component
	// GuardBinary is the Keylatch binary the installed hook runs, when it
	// could be read from the hook command.
	GuardBinary string
}

// Inspect reads the harness's files and reports what is installed.
func Inspect(d Descriptor, e Env) Status {
	layout := d.Layout(e)
	st := Status{Harness: d}
	if _, err := os.Stat(filepath.Join(layout.Dir, d.Detect)); err == nil {
		st.Detected = true
	}
	if d.Hook != nil {
		st.Hook = Component{Path: layout.Hook}
		st.Hook.Present, st.GuardBinary, st.Hook.Err = inspectHook(d, layout.Hook)
	}
	if d.MCP != nil {
		st.MCP = Component{Path: layout.MCP}
		st.MCP.Present, st.MCP.Err = inspectMCP(d, layout.MCP)
	}
	if d.Rules != nil && layout.Rules != "" {
		st.Rules = Component{Path: layout.Rules}
		if data, err := os.ReadFile(layout.Rules); err == nil { //nolint:gosec // G304: the harness's own rules file
			st.Rules.Present = bytes.Contains(data, []byte(merge.MarkdownBegin))
		}
	}
	return st
}

func inspectHook(d Descriptor, path string) (present bool, binary string, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the harness's own hook file
	if os.IsNotExist(err) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	marker := GuardMarker(d)
	if d.Hook.Format == FormatPluginDir {
		return bytes.Contains(data, []byte("keylatch guard hook")), pluginBinary(data), nil
	}
	root, err := merge.ParseJSON(data)
	if err != nil {
		return false, "", err
	}
	if plan, ok := hookPlanFor(d); ok {
		if !hasGuard(root, plan, marker) {
			return false, "", nil
		}
		return true, guardBinary(root, plan, marker), nil
	}
	// Claude Code: the guard package installs it; look for the marker anywhere.
	cmd := findMarker(root, marker)
	return cmd != "", binaryOf(cmd), nil
}

func inspectMCP(d Descriptor, path string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the harness's own MCP file
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if d.MCP.Format == FormatTOML {
		return bytes.Contains(data, []byte(merge.BlockBegin)), nil
	}
	root, err := merge.ParseJSON(data)
	if err != nil {
		return false, err
	}
	v, ok := root.Get(d.MCP.Key)
	if !ok {
		return false, nil
	}
	servers, ok := v.(*merge.Object)
	if !ok {
		return false, nil
	}
	_, present := servers.Get("keylatch")
	return present, nil
}

func guardBinary(root *merge.Object, plan hookPlan, marker string) string {
	var cmd string
	if v, ok := root.Get(plan.container); ok {
		if c, ok := v.(*merge.Object); ok {
			for _, e := range plan.entries {
				arr, _ := c.List(e.event)
				walkLeaves(arr, func(leaf *merge.Object, key string) {
					if s, _ := leaf.Get(key); cmd == "" {
						if str, _ := s.(string); strings.HasSuffix(str, marker) {
							cmd = str
						}
					}
				})
			}
		}
	}
	return binaryOf(cmd)
}

func findMarker(v any, marker string) string {
	switch t := v.(type) {
	case string:
		if strings.HasSuffix(t, marker) {
			return t
		}
	case []any:
		for _, e := range t {
			if s := findMarker(e, marker); s != "" {
				return s
			}
		}
	case *merge.Object:
		for _, k := range t.Keys() {
			child, _ := t.Get(k)
			if s := findMarker(child, marker); s != "" {
				return s
			}
		}
	}
	return ""
}

// binaryOf extracts the quoted binary path a guard command starts with.
func binaryOf(command string) string {
	if !strings.HasPrefix(command, `"`) {
		return ""
	}
	var b strings.Builder
	escaped := false
	for _, r := range command[1:] {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			return b.String()
		default:
			b.WriteRune(r)
		}
	}
	return ""
}

func pluginBinary(data []byte) string {
	const prefix = "const KEYLATCH = "
	i := bytes.Index(data, []byte(prefix))
	if i < 0 {
		return ""
	}
	rest := data[i+len(prefix):]
	end := bytes.IndexByte(rest, ';')
	if end < 0 {
		return ""
	}
	var s string
	if json.Unmarshal(rest[:end], &s) != nil {
		return ""
	}
	return s
}
