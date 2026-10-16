// Package sync keeps deploy secrets (Vercel environment variables, GitHub
// Actions secrets, local env files) in step with the secret manager they come
// from. The manifest says which connection feeds which variable of which
// target; the comparison reports adds, updates and extras by name; the daemon
// does every read of a value and every write to a target.
package sync

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Target types.
const (
	TypeVercel  = "vercel"
	TypeGitHub  = "github-actions"
	TypeEnvFile = "env-file"
)

// Environment names with a fixed meaning.
const (
	EnvRepository = "repository"
	EnvFile       = "file"
)

var vercelEnvs = []string{"production", "preview", "development"}

// DefaultFile is the manifest name at the repository root.
const DefaultFile = "keylatch.sync.yaml"

// Manifest is a parsed keylatch.sync.yaml.
type Manifest struct {
	Version int               `yaml:"version" json:"version"`
	Targets map[string]Target `yaml:"targets" json:"targets"`
	Vars    []Var             `yaml:"vars" json:"vars"`
}

// Target is a place variables are written to.
type Target struct {
	Type         string   `yaml:"type" json:"type"`
	Project      string   `yaml:"project,omitempty" json:"project,omitempty"`
	Team         string   `yaml:"team,omitempty" json:"team,omitempty"`
	Link         string   `yaml:"link,omitempty" json:"link,omitempty"`
	Repo         string   `yaml:"repo,omitempty" json:"repo,omitempty"`
	Environments []string `yaml:"environments,omitempty" json:"environments,omitempty"`
	Path         string   `yaml:"path,omitempty" json:"path,omitempty"`
	// Credential names the Keylatch connection the daemon uses for the target's API.
	Credential string `yaml:"credential,omitempty" json:"credential,omitempty"`
}

// Var is one variable and everywhere it goes.
type Var struct {
	Name      string              `yaml:"name" json:"name"`
	From      Source              `yaml:"from" json:"from"`
	Sensitive *bool               `yaml:"sensitive,omitempty" json:"sensitive,omitempty"`
	To        map[string][]string `yaml:"to" json:"to"`
	Verify    *Probe              `yaml:"verify,omitempty" json:"verify,omitempty"`
}

// Source says where a value comes from.
type Source struct {
	Connection string `yaml:"connection" json:"connection"`
	Field      string `yaml:"field,omitempty" json:"field,omitempty"`
}

// Probe is the request a rotation makes with the new value to prove it works.
type Probe struct {
	URL string `yaml:"url" json:"url"`
}

// IsSensitive reports the Vercel type: sensitive unless the variable says no.
func (v Var) IsSensitive() bool { return v.Sensitive == nil || *v.Sensitive }

// RepoChecker answers the questions about the repository that env-file paths
// depend on.
type RepoChecker interface {
	// Ignored reports that git ignores rel (a slash path below the repository root).
	Ignored(rel string) (bool, error)
	// Tracked reports that git tracks rel.
	Tracked(rel string) (bool, error)
}

var (
	varName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	repoName   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	ghEnvName  = regexp.MustCompile(`^[A-Za-z0-9_. -]{1,255}$`)
	allowedKey = map[string][]string{
		"manifest": {"version", "targets", "vars"},
		"target":   {"type", "project", "team", "link", "repo", "environments", "path", "credential"},
		"var":      {"name", "from", "sensitive", "to", "verify"},
		"from":     {"connection", "field"},
		"verify":   {"url"},
	}
)

// Parse decodes a manifest, rejecting unknown keys with their key path, and
// validates it. repo may be nil to skip the env-file git checks.
func Parse(data []byte, repo RepoChecker) (Manifest, error) {
	var root yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&root); err != nil {
		return Manifest{}, fmt.Errorf("sync manifest: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return Manifest{}, errors.New("sync manifest: the document must be a mapping")
	}
	if err := checkShape(root.Content[0]); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := root.Content[0].Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("sync manifest: %w", err)
	}
	return m, m.Validate(repo)
}

func mapping(n *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	if n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1]
	}
	return out
}

func unknownKeys(n *yaml.Node, path, kind string) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: must be a mapping", path)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i].Value
		if !slices.Contains(allowedKey[kind], k) {
			return fmt.Errorf("%s: unknown key %q", join(path, k), k)
		}
	}
	return nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func checkShape(n *yaml.Node) error {
	if err := unknownKeys(n, "", "manifest"); err != nil {
		return err
	}
	top := mapping(n)
	if t, ok := top["targets"]; ok {
		if t.Kind != yaml.MappingNode {
			return errors.New("targets: must be a mapping")
		}
		for name, tn := range mapping(t) {
			if err := unknownKeys(tn, "targets."+name, "target"); err != nil {
				return err
			}
		}
	}
	if v, ok := top["vars"]; ok {
		if v.Kind != yaml.SequenceNode {
			return errors.New("vars: must be a list")
		}
		for i, vn := range v.Content {
			p := fmt.Sprintf("vars[%d]", i)
			if err := unknownKeys(vn, p, "var"); err != nil {
				return err
			}
			vm := mapping(vn)
			for _, sub := range []string{"from", "verify"} {
				if sn, ok := vm[sub]; ok {
					if err := unknownKeys(sn, join(p, sub), sub); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// Validate checks every rule of the manifest.
func (m Manifest) Validate(repo RepoChecker) error {
	if m.Version != 1 {
		return errors.New("version: must be 1")
	}
	if len(m.Targets) == 0 {
		return errors.New("targets: at least one target is required")
	}
	for _, name := range m.TargetNames() {
		if err := m.Targets[name].validate("targets."+name, repo); err != nil {
			return err
		}
	}
	if len(m.Vars) == 0 {
		return errors.New("vars: at least one variable is required")
	}
	seen := map[string]string{}
	for i, v := range m.Vars {
		if err := m.validateVar(fmt.Sprintf("vars[%d]", i), v, seen); err != nil {
			return err
		}
	}
	return nil
}

// TargetNames lists the targets in a stable order.
func (m Manifest) TargetNames() []string {
	names := make([]string, 0, len(m.Targets))
	for n := range m.Targets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (t Target) validate(at string, repo RepoChecker) error {
	forbid := func(field, val string) error {
		if val != "" {
			return fmt.Errorf("%s.%s: not valid for a %s target", at, field, t.Type)
		}
		return nil
	}
	switch t.Type {
	case TypeVercel:
		if (t.Project == "") == (t.Link == "") {
			return fmt.Errorf("%s: a vercel target needs exactly one of project and link", at)
		}
		if t.Credential == "" {
			return fmt.Errorf("%s.credential: required", at)
		}
		if t.Link != "" {
			if err := validateLinkPath(at+".link", t.Link); err != nil {
				return err
			}
		}
		for _, f := range [][2]string{{"repo", t.Repo}, {"path", t.Path}} {
			if err := forbid(f[0], f[1]); err != nil {
				return err
			}
		}
		if len(t.Environments) > 0 {
			return fmt.Errorf("%s.environments: not valid for a vercel target", at)
		}
	case TypeGitHub:
		if !repoName.MatchString(t.Repo) {
			return fmt.Errorf("%s.repo: must be owner/name", at)
		}
		if t.Credential == "" {
			return fmt.Errorf("%s.credential: required", at)
		}
		for _, f := range [][2]string{{"project", t.Project}, {"team", t.Team}, {"link", t.Link}, {"path", t.Path}} {
			if err := forbid(f[0], f[1]); err != nil {
				return err
			}
		}
		for i, e := range t.Environments {
			if !ghEnvName.MatchString(e) || e == EnvRepository {
				return fmt.Errorf("%s.environments[%d]: %q is not an environment name", at, i, e)
			}
		}
	case TypeEnvFile:
		for _, f := range [][2]string{{"project", t.Project}, {"team", t.Team}, {"link", t.Link}, {"repo", t.Repo}, {"credential", t.Credential}} {
			if err := forbid(f[0], f[1]); err != nil {
				return err
			}
		}
		if len(t.Environments) > 0 {
			return fmt.Errorf("%s.environments: not valid for an env-file target", at)
		}
		return validateEnvFilePath(at+".path", t.Path, repo)
	default:
		return fmt.Errorf("%s.type: %q is not vercel, github-actions or env-file", at, t.Type)
	}
	return nil
}

// validateLinkPath checks the path of a .vercel/project.json the daemon's
// client reads: relative, inside the repository, and with no ".." element at
// all, so a path that only looks like it stays inside cannot be used to read
// another file's project and team ids.
func validateLinkPath(at, p string) error {
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) || filepath.VolumeName(p) != "" || (len(p) > 1 && p[1] == ':') {
		return fmt.Errorf("%s: must be relative to the repository, not absolute", at)
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return fmt.Errorf("%s: must not contain ..", at)
		}
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("%s: invalid path", at)
	}
	return nil
}

func validateEnvFilePath(at, p string, repo RepoChecker) error {
	if p == "" {
		return fmt.Errorf("%s: required", at)
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) || filepath.VolumeName(p) != "" {
		return fmt.Errorf("%s: must be relative to the repository, not absolute", at)
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == ".." || strings.HasPrefix(clean, "../") || clean == "." {
		return fmt.Errorf("%s: must stay inside the repository", at)
	}
	if repo == nil {
		return nil
	}
	if tracked, err := repo.Tracked(clean); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	} else if tracked {
		return fmt.Errorf("%s: %s is tracked by git; a file that holds secrets must not be", at, clean)
	}
	if ignored, err := repo.Ignored(clean); err != nil {
		return fmt.Errorf("%s: %w", at, err)
	} else if !ignored {
		return fmt.Errorf("%s: %s is not git-ignored; add it to .gitignore first", at, clean)
	}
	return nil
}

// AllowedEnvs lists the environments a target accepts in a variable's `to`.
func (t Target) AllowedEnvs() []string {
	switch t.Type {
	case TypeVercel:
		return vercelEnvs
	case TypeGitHub:
		return append([]string{EnvRepository}, t.Environments...)
	case TypeEnvFile:
		return []string{EnvFile}
	}
	return nil
}

func (m Manifest) validateVar(at string, v Var, seen map[string]string) error {
	if !varName.MatchString(v.Name) {
		return fmt.Errorf("%s.name: %q is not a variable name", at, v.Name)
	}
	if v.From.Connection == "" {
		return fmt.Errorf("%s.from.connection: required", at)
	}
	if len(v.To) == 0 {
		return fmt.Errorf("%s.to: at least one target is required", at)
	}
	if v.Verify != nil && !strings.HasPrefix(v.Verify.URL, "https://") {
		return fmt.Errorf("%s.verify.url: must be an https URL", at)
	}
	targets := make([]string, 0, len(v.To))
	for t := range v.To {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, tn := range targets {
		envs := v.To[tn]
		tp := fmt.Sprintf("%s.to.%s", at, tn)
		t, ok := m.Targets[tn]
		if !ok {
			return fmt.Errorf("%s: unknown target %q", tp, tn)
		}
		if len(envs) == 0 {
			return fmt.Errorf("%s: at least one environment is required", tp)
		}
		for i, e := range envs {
			ep := fmt.Sprintf("%s[%d]", tp, i)
			if !slices.Contains(t.AllowedEnvs(), e) {
				return fmt.Errorf("%s: unknown environment %q for target %q (have %s)", ep, e, tn, strings.Join(t.AllowedEnvs(), ", "))
			}
			if t.Type == TypeVercel && e == "development" && v.IsSensitive() {
				return fmt.Errorf("%s: a sensitive variable cannot go to development (Vercel stores sensitive values for production and preview only); set sensitive: false", ep)
			}
			if t.Type == TypeGitHub {
				if v.Name != strings.ToUpper(v.Name) {
					return fmt.Errorf("%s.name: GitHub secret names must be upper case", at)
				}
				if strings.HasPrefix(v.Name, "GITHUB_") {
					return fmt.Errorf("%s.name: GitHub secret names cannot start with GITHUB_", at)
				}
			}
			key := tn + "\x00" + e + "\x00" + v.Name
			if prev, dup := seen[key]; dup {
				return fmt.Errorf("%s: %s is already declared for %s/%s by %s", ep, v.Name, tn, e, prev)
			}
			seen[key] = at
		}
	}
	return nil
}
