package sync

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var envKeyLine = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=`)

// EnvKeys returns the variable names an env file defines.
func EnvKeys(content []byte) []string {
	var out []string
	for _, l := range strings.Split(string(content), "\n") {
		if m := envKeyLine.FindStringSubmatch(l); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// Git runs git in dir and returns its standard output and exit status (-1
// when git could not run).
type Git func(dir string, args ...string) (out string, code int)

// GitRepo answers the questions the env-file rules ask of a repository.
type GitRepo struct {
	Root string
	Git  Git
}

// Ignored implements RepoChecker.
func (g GitRepo) Ignored(rel string) (bool, error) {
	switch _, code := g.Git(g.Root, "check-ignore", "-q", "--", rel); code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	}
	return false, fmt.Errorf("git could not say whether %s is ignored (is %s a git repository?)", rel, g.Root)
}

// Tracked implements RepoChecker.
func (g GitRepo) Tracked(rel string) (bool, error) {
	switch _, code := g.Git(g.Root, "ls-files", "--error-unmatch", "--", rel); code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	}
	return false, fmt.Errorf("git could not say whether %s is tracked (is %s a git repository?)", rel, g.Root)
}

// Loaded is a manifest read from disk with what only the client can see: the
// project ids of link targets and the variable names of env files.
type Loaded struct {
	Raw       []byte
	Root      string
	Manifest  Manifest
	Links     map[string]string
	LinkTeams map[string]string
	EnvKeys   map[string][]string
}

// ErrNoManifest means there is no manifest at the expected place.
var ErrNoManifest = errors.New("sync: no manifest")

// Load reads and validates the manifest at file, or at DefaultFile in the
// repository containing cwd when file is empty.
func Load(file, cwd string, git Git) (*Loaded, error) {
	dir := cwd
	if file != "" {
		abs, err := filepath.Abs(filepath.Dir(file))
		if err != nil {
			return nil, err
		}
		dir = abs
	}
	root, code := git(dir, "rev-parse", "--show-toplevel")
	if code != 0 || root == "" {
		root = dir
	}
	if file == "" {
		file = filepath.Join(root, DefaultFile)
	}
	raw, err := os.ReadFile(filepath.Clean(file))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoManifest, file)
	}
	if err != nil {
		return nil, err
	}
	m, err := Parse(raw, GitRepo{Root: root, Git: git})
	if err != nil {
		return nil, err
	}
	l := &Loaded{Raw: raw, Root: root, Manifest: m, Links: map[string]string{}, LinkTeams: map[string]string{}, EnvKeys: map[string][]string{}}
	for _, name := range m.TargetNames() {
		t := m.Targets[name]
		switch {
		case t.Type == TypeVercel && t.Link != "":
			project, team, err := ReadVercelLink(filepath.Join(root, filepath.FromSlash(t.Link)))
			if err != nil {
				return nil, fmt.Errorf("targets.%s.link: %w", name, err)
			}
			l.Links[name], l.LinkTeams[name] = project, team
		case t.Type == TypeEnvFile:
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(t.Path)))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("targets.%s.path: %w", name, err)
			}
			l.EnvKeys[name] = EnvKeys(data)
		}
	}
	return l, nil
}

// ReadVercelLink reads the project and team ids from a .vercel/project.json.
func ReadVercelLink(path string) (project, team string, err error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", "", err
	}
	var l struct {
		ProjectID string `json:"projectId"`
		OrgID     string `json:"orgId"`
	}
	if err := json.Unmarshal(data, &l); err != nil || l.ProjectID == "" {
		return "", "", errors.New("not a Vercel project link (no projectId)")
	}
	if strings.HasPrefix(l.OrgID, "team_") {
		team = l.OrgID
	}
	return l.ProjectID, team, nil
}
