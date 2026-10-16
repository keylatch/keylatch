package targets

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// rewrite sends every request to the test server, whatever host it names.
type rewrite struct{ to *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	c := req.Clone(req.Context())
	c.URL.Scheme, c.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(c)
}

func clientFor(t *testing.T, h http.Handler) Options {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return Options{Client: &http.Client{Transport: rewrite{u}}}
}

func staticToken(tok string) Token {
	return func(context.Context) (string, error) { return tok, nil }
}

type fakeVercelEnv struct {
	ID, Key, Type string
	Targets       []string
	GitBranch     string
	Integration   string
	Value         string
	Updated       time.Time
}

// fakeVercel implements the slice of the Vercel API the client uses.
type fakeVercel struct {
	mu      sync.Mutex
	token   string
	envs    []*fakeVercelEnv
	nextID  int
	posts   int
	deletes int
	pages   bool
	team    string
}

func (f *fakeVercel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"error":{"code":"forbidden"}}`, http.StatusForbidden)
		return
	}
	if f.team != "" && r.URL.Query().Get("teamId") != f.team {
		http.Error(w, `{"error":{"code":"bad_team"}}`, http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v10/projects/") && strings.HasSuffix(r.URL.Path, "/env"):
		start := 0
		if u := r.URL.Query().Get("until"); u != "" {
			start, _ = strconv.Atoi(u)
		}
		end := len(f.envs)
		var next any
		if f.pages && start == 0 && len(f.envs) > 1 {
			end, next = 1, 1
		}
		var list []map[string]any
		for _, e := range f.envs[start:end] {
			m := map[string]any{"id": e.ID, "key": e.Key, "type": e.Type, "target": e.Targets, "updatedAt": e.Updated.UnixMilli()}
			if len(e.Targets) == 1 {
				m["target"] = e.Targets[0]
			}
			if e.GitBranch != "" {
				m["gitBranch"] = e.GitBranch
			}
			if e.Integration != "" {
				m["configurationId"] = e.Integration
			}
			list = append(list, m)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"envs": list, "pagination": map[string]any{"next": next}})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/env"):
		var body struct {
			Key, Value, Type string
			Target           []string
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.posts++
		for _, e := range f.envs {
			if e.Key == body.Key && strings.Join(e.Targets, ",") == strings.Join(body.Target, ",") && r.URL.Query().Get("upsert") == "true" {
				e.Value, e.Type, e.Updated = body.Value, body.Type, time.Now().UTC().Add(time.Second)
				w.WriteHeader(http.StatusCreated)
				return
			}
		}
		f.nextID++
		f.envs = append(f.envs, &fakeVercelEnv{ID: "env_" + strconv.Itoa(f.nextID), Key: body.Key, Type: body.Type, Targets: body.Target, Value: body.Value, Updated: time.Now().UTC().Add(time.Second)})
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/env/"):
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		for i, e := range f.envs {
			if e.ID == id {
				f.envs = append(f.envs[:i], f.envs[i+1:]...)
				f.deletes++
				return
			}
		}
		http.Error(w, `{"error":{"code":"not_found"}}`, http.StatusNotFound)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v1/projects/") && strings.Contains(r.URL.Path, "/env/"):
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		for _, e := range f.envs {
			if e.ID == id {
				_ = json.NewEncoder(w).Encode(map[string]string{"value": e.Value})
				return
			}
		}
		http.Error(w, `{"error":{"code":"not_found"}}`, http.StatusNotFound)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
	}
}

type fakeGitHub struct {
	mu       sync.Mutex
	token    string
	pub, prv [32]byte
	secrets  map[string]map[string]string // scope -> name -> decrypted value
	updated  map[string]time.Time         // scope/name -> time
	puts     int
	deletes  int
	badKey   bool
}

func newFakeGitHub(t *testing.T, token string) *fakeGitHub {
	t.Helper()
	pub, prv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeGitHub{token: token, pub: *pub, prv: *prv, secrets: map[string]map[string]string{}, updated: map[string]time.Time{}}
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+f.token || r.Header.Get("X-GitHub-Api-Version") == "" {
		http.Error(w, `{}`, http.StatusUnauthorized)
		return
	}
	p := r.URL.Path
	scopeOf := func(p string) string {
		if i := strings.Index(p, "/environments/"); i >= 0 {
			rest := p[i+len("/environments/"):]
			name, _, _ := strings.Cut(rest, "/")
			s, _ := url.PathUnescape(name)
			return s
		}
		return "repository"
	}
	switch {
	case p == "/repos/acme/app" && r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]int{"id": 4242})
	case strings.HasSuffix(p, "/public-key") && r.Method == http.MethodGet:
		key := base64.StdEncoding.EncodeToString(f.pub[:])
		if f.badKey {
			key = "!!"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "kid-1", "key": key})
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/secrets"):
		scope := scopeOf(p)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		var all []map[string]any
		for name := range f.secrets[scope] {
			all = append(all, map[string]any{"name": name, "updated_at": f.updated[scope+"/"+name].Format(time.RFC3339)})
		}
		const per = 100
		lo := (page - 1) * per
		if lo > len(all) {
			lo = len(all)
		}
		hi := lo + per
		if hi > len(all) {
			hi = len(all)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": all[lo:hi]})
	case r.Method == http.MethodPut && strings.Contains(p, "/secrets/"):
		var body struct {
			EncryptedValue string `json:"encrypted_value"`
			KeyID          string `json:"key_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ct, err := base64.StdEncoding.DecodeString(body.EncryptedValue)
		if err != nil || body.KeyID != "kid-1" {
			http.Error(w, `{}`, http.StatusUnprocessableEntity)
			return
		}
		plain, ok := box.OpenAnonymous(nil, ct, &f.pub, &f.prv)
		if !ok {
			http.Error(w, `{}`, http.StatusUnprocessableEntity)
			return
		}
		scope := scopeOf(p)
		name := p[strings.LastIndex(p, "/")+1:]
		if f.secrets[scope] == nil {
			f.secrets[scope] = map[string]string{}
		}
		f.secrets[scope][name] = string(plain)
		f.updated[scope+"/"+name] = time.Now().UTC().Add(time.Second)
		f.puts++
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodDelete && strings.Contains(p, "/secrets/"):
		scope := scopeOf(p)
		name := p[strings.LastIndex(p, "/")+1:]
		if _, ok := f.secrets[scope][name]; !ok {
			http.Error(w, `{}`, http.StatusNotFound)
			return
		}
		delete(f.secrets[scope], name)
		f.deletes++
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected "+r.Method+" "+p, http.StatusTeapot)
	}
}
