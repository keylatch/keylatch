// Package mintsessiontest provides a fake GitHub App API and an in-memory
// connection store holding a throwaway App key, for tests of code that mints
// installation tokens.
package mintsessiontest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/connections"
)

// Owner is the account the fake App is installed on.
const Owner = "patrikmichi"

// Token returns the n-th token the fake API issues, counting from one.
func Token(n int) string {
	return fmt.Sprintf("ghs_mintedTestToken%03d0123456789abcdefghij", n)
}

// Stub is a fake GitHub App API that issues tokens and records revocations.
type Stub struct {
	URL string

	// Lifetime is how long issued tokens live; zero means one hour.
	Lifetime time.Duration
	// Widen makes the API grant more than was asked for.
	Widen bool
	// Log, when set, receives one line per mint and per revocation.
	Log io.Writer

	srv     *httptest.Server
	mu      sync.Mutex
	posts   []map[string]any
	revokes []string
}

// NewStub starts the fake API; call Close when done.
func NewStub() *Stub {
	s := &Stub{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	s.URL = s.srv.URL
	return s
}

// Close stops the fake API.
func (s *Stub) Close() { s.srv.Close() }

// Mints returns the token requests received so far.
func (s *Stub) Mints() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.posts...)
}

// Revoked returns the tokens revoked so far.
func (s *Stub) Revoked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.revokes...)
}

func (s *Stub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/app/installations/777/access_tokens":
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.posts = append(s.posts, req)
		perms := req["permissions"].(map[string]any)
		if s.Widen {
			perms["workflows"] = "write"
		}
		var repos []map[string]any
		for _, n := range req["repositories"].([]any) {
			repos = append(repos, map[string]any{"full_name": Owner + "/" + n.(string)})
		}
		if s.Log != nil {
			_, _ = fmt.Fprintf(s.Log, "mint %d %v\n", len(s.posts), req["repositories"])
		}
		life := s.Lifetime
		if life == 0 {
			life = time.Hour
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":        Token(len(s.posts)),
			"expires_at":   time.Now().Add(life).UTC().Format(time.RFC3339),
			"permissions":  perms,
			"repositories": repos,
		})
	case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
		s.revokes = append(s.revokes, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if s.Log != nil {
			_, _ = fmt.Fprintf(s.Log, "revoke %s\n", s.revokes[len(s.revokes)-1])
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// Store is a read-only connection store holding one github-app connection.
type Store struct {
	mu   sync.Mutex
	data map[string][]byte
	gets int
}

// NewStore returns a store with a fresh App key, the App ID and the
// installation of Owner.
func NewStore() (*Store, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return &Store{data: map[string][]byte{
		connections.SecretFieldPath("default", "code-hosting", "github-app", "private_key"):         keyPEM,
		connections.ConfigFieldPath("default", "code-hosting", "github-app", "app_id"):              []byte("1234"),
		connections.ConfigFieldPath("default", "code-hosting", "github-app", "installation_"+Owner): []byte("777"),
	}}, nil
}

// Reads is the number of reads served, so tests can prove nothing touched key
// material.
func (s *Store) Reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

// Get returns the stored value.
func (s *Store) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	v, ok := s.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return bytes.Clone(v), backend.Meta{Path: path}, nil
}

// Set is refused: the store is read-only.
func (s *Store) Set(context.Context, string, []byte, backend.Meta) error {
	return errors.New("read-only")
}

// List returns nothing.
func (s *Store) List(context.Context, string) ([]backend.Entry, error) { return nil, nil }

// Delete is a no-op.
func (s *Store) Delete(context.Context, string) error { return nil }
