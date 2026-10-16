package targets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	keysync "github.com/keylatch/keylatch/internal/sync"
)

// EnvFileIO is an env file handed to a write: its current content and where
// the merged content goes.
type EnvFileIO struct {
	Existing []byte
	Flush    func([]byte) error
}

// BuildOptions says how to reach each target of a manifest.
type BuildOptions struct {
	// Credential returns the API token held by a connection.
	Credential func(ctx context.Context, connection string) (string, error)
	HTTP       *http.Client
	// Links and LinkTeams hold the project and team ids the client read from
	// the link files of `link` targets.
	Links     map[string]string
	LinkTeams map[string]string
	// Root names env files in the record of writes.
	Root string
	// EnvKeys are the variable names of env files whose content is not handed
	// over; such a target can be listed and not written.
	EnvKeys map[string][]string
	// EnvFiles are the env files whose content is handed over.
	EnvFiles map[string]EnvFileIO
	// Override replaces the client for a target; ok=false builds the real one.
	Override func(name string, t keysync.Target, token Token) (keysync.TargetClient, bool)
}

// Build returns a client for every target of the manifest.
func Build(m keysync.Manifest, o BuildOptions) (map[string]keysync.TargetClient, error) {
	out := map[string]keysync.TargetClient{}
	opt := Options{Client: o.HTTP}
	for _, name := range m.TargetNames() {
		t := m.Targets[name]
		token := func(ctx context.Context) (string, error) { return o.Credential(ctx, t.Credential) }
		if o.Override != nil {
			if c, ok := o.Override(name, t, token); ok {
				out[name] = c
				continue
			}
		}
		switch t.Type {
		case keysync.TypeVercel:
			project, team := t.Project, t.Team
			if project == "" {
				project = o.Links[name]
				if team == "" {
					team = o.LinkTeams[name]
				}
			}
			if project == "" {
				return nil, fmt.Errorf("targets.%s: the link file was not read", name)
			}
			out[name] = NewVercel(project, team, token, opt)
		case keysync.TypeGitHub:
			owner, repo, _ := strings.Cut(t.Repo, "/")
			out[name] = NewGitHub(owner, repo, t.Environments, token, opt)
		case keysync.TypeEnvFile:
			id := "envfile:" + path.Join(o.Root, t.Path)
			if f, ok := o.EnvFiles[name]; ok {
				out[name] = NewEnvFile(id, f.Existing, f.Flush)
			} else {
				out[name] = NamesOnly{TargetID: id, Names: o.EnvKeys[name]}
			}
		}
	}
	return out, nil
}

// NamesOnly stands for an env file whose content was not handed over: it lists
// the names the client read and refuses to change anything.
type NamesOnly struct {
	TargetID string
	Names    []string
}

var errNoFile = errors.New("the env file was not handed over")

func (e NamesOnly) ID() string { return e.TargetID }

func (e NamesOnly) List(context.Context) ([]keysync.Remote, error) {
	out := make([]keysync.Remote, 0, len(e.Names))
	for _, n := range e.Names {
		out = append(out, keysync.Remote{Name: n, Environments: []string{keysync.EnvFile}})
	}
	return out, nil
}

func (NamesOnly) Write(context.Context, string, []byte, []string, bool) error { return errNoFile }
func (NamesOnly) Delete(context.Context, keysync.Remote) error                { return errNoFile }
func (NamesOnly) Readback(context.Context, keysync.Remote) ([]byte, bool, error) {
	return nil, false, nil
}
