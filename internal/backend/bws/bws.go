// Package bws implements a read-only Backend over Bitwarden Secrets Manager.
//
// Keylatch holds the machine-account access token and hands it to the bws CLI
// in the CLI's environment, never on its command line. The CLI runs with a
// private home so its state file does not land in the user's account. Values
// are read at use time and never stored. Writes are refused: the CLI takes a
// secret's value as an argument, which would put it in the process list.
package bws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

var _ backend.Backend = (*Backend)(nil)

const callTimeout = 30 * time.Second

// uuid is how Secrets Manager names its secrets and projects.
var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Runner runs the bws CLI with exactly the environment it is given.
type Runner interface {
	Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
}

// ExecRunner runs the CLI on the host.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	path := name
	if !filepath.IsAbs(path) {
		if path = kexec.Resolve(name); path == "" {
			return nil, fmt.Errorf("%s not found in PATH", name)
		}
	}
	out, stderr, code, err := kexec.RunExact(ctx, path, args, env)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		// The CLI's own message is useful; it does not echo the token.
		return nil, fmt.Errorf("exit status %d: %s", code, strings.TrimSpace(string(stderr)))
	}
	return out, nil
}

// Options configures a Backend.
type Options struct {
	// AccessToken is the machine-account token, held by Keylatch.
	AccessToken string
	// ProjectID scopes the backend to one project.
	ProjectID string
	// ServerURL is the Bitwarden server for self-hosted installs.
	ServerURL string
	// Bin is the bws executable; "bws" when empty.
	Bin    string
	Runner Runner
	// Env supplies PATH and, on Windows, SystemRoot to the CLI.
	Env func(string) string
}

// Backend is a read-only view of one Secrets Manager project.
type Backend struct {
	opts Options
	run  Runner

	mu      sync.Mutex
	workDir string
	closed  bool
}

type secret struct {
	ID        string `json:"id"`
	ProjectID string `json:"projectId"`
	Key       string `json:"key"`
	Value     string `json:"value"`
}

// Open validates opts and returns a Backend.
func Open(opts Options) (*Backend, error) {
	switch {
	case opts.AccessToken == "":
		return nil, errors.New("bws backend: an access token is required (store it with 'keylatch backend login bws')")
	case !uuid.MatchString(opts.ProjectID):
		return nil, errors.New("bws backend: project_id must be the project's UUID")
	case opts.ServerURL != "" && !strings.HasPrefix(opts.ServerURL, "https://"):
		return nil, errors.New("bws backend: server_url must use https")
	}
	if opts.Bin == "" {
		opts.Bin = "bws"
	}
	b := &Backend{opts: opts, run: opts.Runner}
	if b.run == nil {
		b.run = ExecRunner{}
	}
	return b, nil
}

// Name implements backend.Backend.
func (*Backend) Name() string { return "bws" }

// Capabilities implements backend.Backend.
func (*Backend) Capabilities() []backend.Capability {
	return []backend.Capability{backend.CapList, backend.CapNetworkedFetch}
}

// ID implements backend.Backend.
func (b *Backend) ID() string { return "bws:" + b.opts.ProjectID }

// home returns the private directory the CLI keeps its state in.
func (b *Backend) home() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return "", errors.New("bws backend: closed")
	}
	if b.workDir == "" {
		d, err := os.MkdirTemp("", "keylatch-bws-")
		if err != nil {
			return "", err
		}
		b.workDir = d
	}
	return b.workDir, nil
}

// environ is the whole environment of a CLI call: the token, a private home and
// the PATH, nothing else of the caller's.
func (b *Backend) environ(home string) []string {
	env := []string{
		"BWS_ACCESS_TOKEN=" + b.opts.AccessToken,
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + home,
		"USERPROFILE=" + home,
		"APPDATA=" + home,
	}
	get := b.opts.Env
	if get == nil {
		get = os.Getenv
	}
	if p := get("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	if runtime.GOOS == "windows" {
		if r := get("SystemRoot"); r != "" {
			env = append(env, "SystemRoot="+r)
		}
	}
	return env
}

func (b *Backend) call(ctx context.Context, args ...string) ([]byte, error) {
	home, err := b.home()
	if err != nil {
		return nil, err
	}
	if b.opts.ServerURL != "" {
		args = append(args, "--server-url", b.opts.ServerURL)
	}
	args = append(args, "--output", "json", "--color", "no")
	return b.run.Run(ctx, b.environ(home), b.opts.Bin, args...)
}

func (b *Backend) list(ctx context.Context) ([]secret, error) {
	out, err := b.call(ctx, "secret", "list", b.opts.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("bws list: %w", err)
	}
	var ss []secret
	if err := json.Unmarshal(out, &ss); err != nil {
		return nil, fmt.Errorf("bws list: decode: %w", err)
	}
	return ss, nil
}

// Get returns the value of the secret whose key is path, or of the secret with
// that UUID. A key that names several secrets is refused rather than guessed.
func (b *Backend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	var s secret
	if uuid.MatchString(path) {
		out, err := b.call(ctx, "secret", "get", path)
		if err != nil {
			return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		}
		if err := json.Unmarshal(out, &s); err != nil {
			return nil, backend.Meta{}, fmt.Errorf("bws get: decode: %w", err)
		}
		if s.ProjectID != "" && !strings.EqualFold(s.ProjectID, b.opts.ProjectID) {
			return nil, backend.Meta{}, fmt.Errorf("%w: %s is outside the configured project", backend.ErrNotFound, path)
		}
	} else {
		all, err := b.list(ctx)
		if err != nil {
			return nil, backend.Meta{}, err
		}
		var match []secret
		for _, c := range all {
			if c.Key == path {
				match = append(match, c)
			}
		}
		switch len(match) {
		case 0:
			return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		case 1:
			s = match[0]
		default:
			return nil, backend.Meta{}, fmt.Errorf("bws: %d secrets are named %q; use a secret UUID", len(match), path)
		}
	}
	return []byte(s.Value), backend.Meta{Path: path, Backend: "bws", Version: 1}, nil
}

// List returns the keys of the project's secrets. Values are not kept.
func (b *Backend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	all, err := b.list(ctx)
	if err != nil {
		return nil, err
	}
	var out []backend.Entry
	for _, s := range all {
		if strings.HasPrefix(s.Key, prefix) {
			out = append(out, backend.Entry{Meta: backend.Meta{Path: s.Key, Backend: "bws", Version: 1}, Exists: true})
		}
	}
	return out, nil
}

var errReadOnly = fmt.Errorf("bws backend is read-only: the CLI takes a value as an argument, which would expose it in the process list; %w", backend.ErrNotSupported)

// Set is refused.
func (*Backend) Set(context.Context, string, []byte, backend.Meta) error { return errReadOnly }

// Delete is refused.
func (*Backend) Delete(context.Context, string) error { return errReadOnly }

// GetMeta is not supported.
func (*Backend) GetMeta(context.Context, string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported.
func (*Backend) SetMeta(context.Context, string, vmeta.Meta) error { return backend.ErrNotSupported }

// ListMeta is not supported.
func (*Backend) ListMeta(context.Context, string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported.
func (*Backend) GetVersioned(context.Context, string, int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported.
func (*Backend) SetVersioned(context.Context, string, int, []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported.
func (*Backend) DeleteVersioned(context.Context, string, int) error {
	return backend.ErrNotSupported
}

// Close removes the CLI's private home. It is safe to call twice.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.workDir == "" {
		return nil
	}
	err := os.RemoveAll(b.workDir)
	b.workDir = ""
	return err
}
