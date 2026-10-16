package targets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/crypto/nacl/box"

	keysync "github.com/keylatch/keylatch/internal/sync"
)

const githubDefaultBase = "https://api.github.com"

// GitHub manages the Actions secrets of one repository and the environments
// it names.
type GitHub struct {
	api          *api
	owner, repo  string
	environments []string

	repoID int64
	keys   map[string]publicKey
}

type publicKey struct {
	ID  string `json:"key_id"`
	Key string `json:"key"`
}

// NewGitHub returns a client for owner/repo and the named environments.
func NewGitHub(owner, repo string, environments []string, token Token, opt Options) *GitHub {
	return &GitHub{
		api: &api{
			base: apiBase("github", githubDefaultBase), http: opt.client(), token: token,
			headers: map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
		},
		owner: owner, repo: repo, environments: environments,
		keys: map[string]publicKey{},
	}
}

// ID is the identity the daemon keys its record of writes by.
func (g *GitHub) ID() string { return "github:" + g.owner + "/" + g.repo }

func (g *GitHub) repoPath() string {
	return "/repos/" + url.PathEscape(g.owner) + "/" + url.PathEscape(g.repo)
}

func (g *GitHub) secretsPath(scope string) string {
	if scope == keysync.EnvRepository {
		return g.repoPath() + "/actions/secrets"
	}
	return g.repoPath() + "/environments/" + url.PathEscape(scope) + "/secrets"
}

func (g *GitHub) listScope(ctx context.Context, scope string) ([]keysync.Remote, error) {
	var out []keysync.Remote
	for page := 1; page < 1000; page++ {
		var resp struct {
			Secrets []struct {
				Name      string    `json:"name"`
				UpdatedAt time.Time `json:"updated_at"`
			} `json:"secrets"`
		}
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if err := g.api.do(ctx, http.MethodGet, g.secretsPath(scope), q, nil, &resp); err != nil {
			return nil, err
		}
		for _, s := range resp.Secrets {
			out = append(out, keysync.Remote{Name: s.Name, Environments: []string{scope}, UpdatedAt: s.UpdatedAt})
		}
		if len(resp.Secrets) < 100 {
			break
		}
	}
	return out, nil
}

// List returns the repository's secrets and those of each configured environment.
func (g *GitHub) List(ctx context.Context) ([]keysync.Remote, error) {
	out, err := g.listScope(ctx, keysync.EnvRepository)
	if err != nil {
		return nil, err
	}
	for _, e := range g.environments {
		more, err := g.listScope(ctx, e)
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
	}
	return out, nil
}

func (g *GitHub) repositoryID(ctx context.Context) (int64, error) {
	if g.repoID != 0 {
		return g.repoID, nil
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := g.api.do(ctx, http.MethodGet, g.repoPath(), nil, nil, &resp); err != nil {
		return 0, err
	}
	g.repoID = resp.ID
	return resp.ID, nil
}

func (g *GitHub) publicKey(ctx context.Context, scope string) (publicKey, error) {
	if k, ok := g.keys[scope]; ok {
		return k, nil
	}
	path := g.secretsPath(scope) + "/public-key"
	if scope != keysync.EnvRepository {
		id, err := g.repositoryID(ctx)
		if err != nil {
			return publicKey{}, err
		}
		path = "/repositories/" + strconv.FormatInt(id, 10) + "/environments/" + url.PathEscape(scope) + "/secrets/public-key"
	}
	var k publicKey
	if err := g.api.do(ctx, http.MethodGet, path, nil, nil, &k); err != nil {
		return publicKey{}, err
	}
	g.keys[scope] = k
	return k, nil
}

func seal(k publicKey, value []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(k.Key)
	if err != nil || len(raw) != 32 {
		return "", errors.New("github: the repository public key is malformed")
	}
	var pub [32]byte
	copy(pub[:], raw)
	ct, err := box.SealAnonymous(nil, value, &pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Write seals value to each scope's public key and stores it as a secret.
// GitHub secrets are always write-only, so sensitive has no effect.
func (g *GitHub) Write(ctx context.Context, name string, value []byte, envs []string, _ bool) error {
	for _, scope := range envs {
		k, err := g.publicKey(ctx, scope)
		if err != nil {
			return err
		}
		sealed, err := seal(k, value)
		if err != nil {
			return err
		}
		path := g.secretsPath(scope) + "/" + url.PathEscape(name)
		if scope != keysync.EnvRepository {
			id, err := g.repositoryID(ctx)
			if err != nil {
				return err
			}
			path = "/repositories/" + strconv.FormatInt(id, 10) + "/environments/" + url.PathEscape(scope) + "/secrets/" + url.PathEscape(name)
		}
		if err := g.api.do(ctx, http.MethodPut, path, nil, map[string]string{"encrypted_value": sealed, "key_id": k.ID}, nil); err != nil {
			return fmt.Errorf("github secret %s in %s: %w", name, scope, err)
		}
	}
	return nil
}

// Delete removes a secret from the scope the entry was listed in.
func (g *GitHub) Delete(ctx context.Context, r keysync.Remote) error {
	for _, scope := range r.Environments {
		if err := g.api.do(ctx, http.MethodDelete, g.secretsPath(scope)+"/"+url.PathEscape(r.Name), nil, nil, nil); err != nil && !IsNotFound(err) {
			return err
		}
	}
	return nil
}

// Readback reports false: GitHub never returns a secret's value.
func (g *GitHub) Readback(context.Context, keysync.Remote) ([]byte, bool, error) {
	return nil, false, nil
}
