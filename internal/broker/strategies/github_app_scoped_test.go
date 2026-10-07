package strategies_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const stubToken = "ghs_stubInstallationToken0123456789abcdef"

var fixedNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

type ghStub struct {
	mu        sync.Mutex
	posts     []map[string]any
	authz     []string
	revokes   []string
	reply     func(req map[string]any) (int, map[string]any)
	revokeErr bool
}

func (g *ghStub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/app/installations/42/access_tokens":
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			require.NoError(t, json.Unmarshal(body, &req))
			g.posts = append(g.posts, req)
			g.authz = append(g.authz, r.Header.Get("Authorization"))
			status, reply := g.reply(req)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(reply)
		case r.Method == http.MethodDelete && r.URL.Path == "/installation/token":
			g.revokes = append(g.revokes, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if g.revokeErr {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// echoReply grants exactly what was requested, for the given owner.
func echoReply(owner string, lifetime time.Duration) func(map[string]any) (int, map[string]any) {
	return func(req map[string]any) (int, map[string]any) {
		var repos []map[string]any
		for _, n := range req["repositories"].([]any) {
			repos = append(repos, map[string]any{"name": n, "full_name": owner + "/" + n.(string)})
		}
		return http.StatusCreated, map[string]any{
			"token":                stubToken,
			"expires_at":           fixedNow.Add(lifetime).Format(time.RFC3339),
			"permissions":          req["permissions"],
			"repository_selection": "selected",
			"repositories":         repos,
		}
	}
}

func newScopedStrategy(t *testing.T, g *ghStub) (*strategies.GitHubAppInstallationStrategy, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	srv := httptest.NewServer(g.handler(t))
	t.Cleanup(srv.Close)
	return strategies.NewGitHubAppInstallationStrategyWithAPI("1234", "42", key, srv.URL, func() time.Time { return fixedNow }), key
}

var readWrite = map[string]string{"contents": "write", "metadata": "read"}

func TestGitHubAppRequestScoped(t *testing.T) {
	g := &ghStub{reply: echoReply("octo", time.Hour)}
	s, key := newScopedStrategy(t, g)

	tok, err := s.MintScoped(context.Background(), strategies.GitHubAppScope{Repository: "octo/repo", Permissions: readWrite}, time.Hour)
	require.NoError(t, err)
	defer tok.Zero()

	require.Len(t, g.posts, 1)
	assert.Equal(t, []any{"repo"}, g.posts[0]["repositories"])
	assert.Equal(t, map[string]any{"contents": "write", "metadata": "read"}, g.posts[0]["permissions"])
	assert.Len(t, g.posts[0], 2, "request carries only repositories and permissions")
	assert.Empty(t, g.revokes)

	assert.Equal(t, stubToken, string(tok.Token))
	assert.Equal(t, "octo/repo", tok.Repository)
	assert.Equal(t, readWrite, tok.Permissions)
	assert.Equal(t, fixedNow.Add(time.Hour), tok.ExpiresAt)

	verifyAppJWT(t, strings.TrimPrefix(g.authz[0], "Bearer "), &key.PublicKey, "1234")
}

func verifyAppJWT(t *testing.T, jwt string, pub *rsa.PublicKey, appID string) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	require.Len(t, parts, 3)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig))
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var c struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	require.NoError(t, json.Unmarshal(claims, &c))
	assert.Equal(t, appID, c.Iss)
	assert.LessOrEqual(t, c.Exp-c.Iat, int64(600))
}

func TestGitHubAppMismatchRevokes(t *testing.T) {
	cases := map[string]func(map[string]any) (int, map[string]any){
		"wider permissions": func(req map[string]any) (int, map[string]any) {
			_, r := echoReply("octo", time.Hour)(req)
			r["permissions"] = map[string]any{"contents": "write", "metadata": "read", "workflows": "write"}
			return http.StatusCreated, r
		},
		"higher permission level": func(req map[string]any) (int, map[string]any) {
			_, r := echoReply("octo", time.Hour)(req)
			r["permissions"] = map[string]any{"contents": "admin", "metadata": "read"}
			return http.StatusCreated, r
		},
		"second repository": func(req map[string]any) (int, map[string]any) {
			_, r := echoReply("octo", time.Hour)(req)
			r["repositories"] = append(r["repositories"].([]map[string]any), map[string]any{"full_name": "octo/other"})
			return http.StatusCreated, r
		},
		"all repositories": func(req map[string]any) (int, map[string]any) {
			_, r := echoReply("octo", time.Hour)(req)
			r["repository_selection"] = "all"
			delete(r, "repositories")
			return http.StatusCreated, r
		},
		"other owner":         echoReply("evil", time.Hour),
		"lifetime over limit": echoReply("octo", 2*time.Hour),
		"no expiry": func(req map[string]any) (int, map[string]any) {
			_, r := echoReply("octo", time.Hour)(req)
			delete(r, "expires_at")
			return http.StatusCreated, r
		},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			g := &ghStub{reply: reply}
			s, _ := newScopedStrategy(t, g)
			tok, err := s.MintScoped(context.Background(), strategies.GitHubAppScope{Repository: "octo/repo", Permissions: readWrite}, time.Hour)
			require.Error(t, err)
			assert.ErrorIs(t, err, strategies.ErrScopeMismatch)
			assert.Nil(t, tok.Token)
			assert.Equal(t, []string{stubToken}, g.revokes, "the issued token is revoked")
			assert.NotContains(t, err.Error(), stubToken)
		})
	}
}

func TestGitHubAppLifetimeBoundedByPolicy(t *testing.T) {
	g := &ghStub{reply: echoReply("octo", time.Hour)}
	s, _ := newScopedStrategy(t, g)
	_, err := s.MintScoped(context.Background(), strategies.GitHubAppScope{Repository: "octo/repo", Permissions: readWrite}, 30*time.Minute)
	require.ErrorIs(t, err, strategies.ErrScopeMismatch)
	assert.Len(t, g.revokes, 1)
}

func TestGitHubAppMismatchRevokeFailureReported(t *testing.T) {
	g := &ghStub{reply: echoReply("evil", time.Hour), revokeErr: true}
	s, _ := newScopedStrategy(t, g)
	_, err := s.MintScoped(context.Background(), strategies.GitHubAppScope{Repository: "octo/repo", Permissions: readWrite}, time.Hour)
	require.ErrorIs(t, err, strategies.ErrScopeMismatch)
	assert.Contains(t, err.Error(), "revoking it failed")
	assert.NotContains(t, err.Error(), stubToken)
}

func TestGitHubAppRefusedRequestNotRevoked(t *testing.T) {
	g := &ghStub{reply: func(map[string]any) (int, map[string]any) {
		return http.StatusUnprocessableEntity, map[string]any{"message": "permissions not granted"}
	}}
	s, _ := newScopedStrategy(t, g)
	_, err := s.MintScoped(context.Background(), strategies.GitHubAppScope{Repository: "octo/repo", Permissions: readWrite}, time.Hour)
	require.Error(t, err)
	assert.False(t, errors.Is(err, strategies.ErrScopeMismatch))
	assert.Contains(t, err.Error(), "422")
	assert.Empty(t, g.revokes)
}

func TestGitHubAppNoCrossScopeCache(t *testing.T) {
	g := &ghStub{reply: echoReply("octo", time.Hour)}
	s, _ := newScopedStrategy(t, g)
	ctx := context.Background()
	a, err := s.MintScoped(ctx, strategies.GitHubAppScope{Repository: "octo/a", Permissions: map[string]string{"contents": "read"}}, time.Hour)
	require.NoError(t, err)
	b, err := s.MintScoped(ctx, strategies.GitHubAppScope{Repository: "octo/b", Permissions: readWrite}, time.Hour)
	require.NoError(t, err)
	_, err = s.MintScoped(ctx, strategies.GitHubAppScope{Repository: "octo/a", Permissions: map[string]string{"contents": "read"}}, time.Hour)
	require.NoError(t, err)

	require.Len(t, g.posts, 3, "every mint reaches GitHub")
	assert.Equal(t, []any{"a"}, g.posts[0]["repositories"])
	assert.Equal(t, []any{"b"}, g.posts[1]["repositories"])
	assert.Equal(t, "octo/a", a.Repository)
	assert.Equal(t, "octo/b", b.Repository)
}

func TestGitHubAppRejectsMalformedScope(t *testing.T) {
	g := &ghStub{reply: echoReply("octo", time.Hour)}
	s, _ := newScopedStrategy(t, g)
	for _, repo := range []string{"", "octo", "octo/", "/repo", "octo/a/b"} {
		_, err := s.MintScoped(context.Background(), strategies.GitHubAppScope{Repository: repo, Permissions: readWrite}, time.Hour)
		assert.Error(t, err, repo)
	}
	_, err := s.MintScoped(context.Background(), strategies.GitHubAppScope{Repository: "octo/repo"}, time.Hour)
	assert.Error(t, err)
	assert.Empty(t, g.posts)
}

func TestParseGitHubAppPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	got, err := strategies.ParseGitHubAppPrivateKey(pkcs1)
	require.NoError(t, err)
	assert.True(t, key.Equal(got))

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	got, err = strategies.ParseGitHubAppPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	require.NoError(t, err)
	assert.True(t, key.Equal(got))

	_, err = strategies.ParseGitHubAppPrivateKey([]byte("not a key"))
	assert.Error(t, err)
}
