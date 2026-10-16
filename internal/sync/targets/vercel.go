package targets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	keysync "github.com/keylatch/keylatch/internal/sync"
)

const vercelDefaultBase = "https://api.vercel.com"

// Vercel manages the environment variables of one project.
type Vercel struct {
	api     *api
	project string
	team    string
}

// NewVercel returns a client for project (an id or a name) in team (empty for
// a personal account).
func NewVercel(project, team string, token Token, opt Options) *Vercel {
	return &Vercel{
		api:     &api{base: apiBase("vercel", vercelDefaultBase), http: opt.client(), token: token},
		project: project,
		team:    team,
	}
}

// ID is the identity the daemon keys its record of writes by.
func (v *Vercel) ID() string { return "vercel:" + v.project }

func (v *Vercel) query(extra ...string) url.Values {
	q := url.Values{}
	if v.team != "" {
		q.Set("teamId", v.team)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	return q
}

type vercelEnv struct {
	ID                   string          `json:"id"`
	Key                  string          `json:"key"`
	Type                 string          `json:"type"`
	Target               json.RawMessage `json:"target"`
	GitBranch            string          `json:"gitBranch"`
	CustomEnvironmentIDs []string        `json:"customEnvironmentIds"`
	ConfigurationID      string          `json:"configurationId"`
	UpdatedAt            int64           `json:"updatedAt"`
}

func (e vercelEnv) targets() []string {
	var many []string
	if json.Unmarshal(e.Target, &many) == nil {
		return many
	}
	var one string
	if json.Unmarshal(e.Target, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

// List returns the project's variables. Entries tied to a git branch, a custom
// environment or an integration, and system variables, are marked unmanaged.
func (v *Vercel) List(ctx context.Context) ([]keysync.Remote, error) {
	var out []keysync.Remote
	until := ""
	for page := 0; page < 100; page++ {
		q := v.query()
		if until != "" {
			q.Set("until", until)
		}
		var resp struct {
			Envs       []vercelEnv `json:"envs"`
			Pagination struct {
				Next *int64 `json:"next"`
			} `json:"pagination"`
		}
		if err := v.api.do(ctx, http.MethodGet, "/v10/projects/"+url.PathEscape(v.project)+"/env", q, nil, &resp); err != nil {
			return nil, err
		}
		for _, e := range resp.Envs {
			r := keysync.Remote{ID: e.ID, Name: e.Key, Environments: e.targets(), Type: e.Type}
			if e.UpdatedAt > 0 {
				r.UpdatedAt = time.UnixMilli(e.UpdatedAt).UTC()
			}
			r.Unmanaged = e.GitBranch != "" || len(e.CustomEnvironmentIDs) > 0 || e.ConfigurationID != "" || e.Type == "system"
			out = append(out, r)
		}
		if resp.Pagination.Next == nil {
			return out, nil
		}
		until = strconv.FormatInt(*resp.Pagination.Next, 10)
	}
	return out, nil
}

// Write sets name to value for envs, as a sensitive or an encrypted variable.
func (v *Vercel) Write(ctx context.Context, name string, value []byte, envs []string, sensitive bool) error {
	typ := "encrypted"
	if sensitive {
		typ = "sensitive"
	}
	body := map[string]any{"key": name, "value": string(value), "type": typ, "target": envs}
	return v.api.do(ctx, http.MethodPost, "/v10/projects/"+url.PathEscape(v.project)+"/env", v.query("upsert", "true"), body, nil)
}

// Delete removes one entry.
func (v *Vercel) Delete(ctx context.Context, r keysync.Remote) error {
	return v.api.do(ctx, http.MethodDelete, "/v9/projects/"+url.PathEscape(v.project)+"/env/"+url.PathEscape(r.ID), v.query(), nil, nil)
}

// Readback returns the value of an encrypted entry. Sensitive entries are
// write-only and report false.
func (v *Vercel) Readback(ctx context.Context, r keysync.Remote) ([]byte, bool, error) {
	if r.Type != "encrypted" {
		return nil, false, nil
	}
	var resp struct {
		Value string `json:"value"`
	}
	if err := v.api.do(ctx, http.MethodGet, "/v1/projects/"+url.PathEscape(v.project)+"/env/"+url.PathEscape(r.ID), v.query(), nil, &resp); err != nil {
		return nil, false, err
	}
	return []byte(resp.Value), true, nil
}
