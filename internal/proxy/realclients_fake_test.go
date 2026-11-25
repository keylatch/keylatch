package proxy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeGitHub stands in for GitHub's three hosts for real git and gh clients.
// It serves git smart HTTP for bare repositories (git http-backend), the few
// REST and GraphQL calls gh makes, and refuses any request that does not carry
// the credential of the installation that owns the path.
type fakeGitHub struct {
	t      *testing.T
	srv    *httptest.Server
	caPool *x509.CertPool
	root   string // bare repositories live at root/<owner>/<name>.git

	mu     sync.Mutex
	tokens map[string]string // owner -> token the fake accepts
	seen   []recordedRequest

	prCreated bool
}

type recordedRequest struct {
	Method, Host, Path, Query, Proto string
	TE                               []string
	Header                           http.Header
	Body                             string // REST and GraphQL bodies only
	Status                           int
}

func newFakeGitHub(t *testing.T, root string, tokens map[string]string) *fakeGitHub {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test upstream CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "github.com"},
		DNSNames:  []string{"github.com", "api.github.com", "uploads.github.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	f := &fakeGitHub{t: t, root: root, tokens: tokens, caPool: x509.NewCertPool()}
	f.caPool.AddCert(caCert)
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.EnableHTTP2 = true
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// transport dials the fake whatever host the proxy asks for, and trusts only
// the test CA. It stands in for the proxy's upstream: DNS plus public roots.
func (f *fakeGitHub) transport() *http.Transport {
	addr := f.srv.Listener.Addr().String()
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: f.caPool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
}

func (f *fakeGitHub) requests() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.seen...)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusRecorder) Flush() {
	if fl, ok := s.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	rec := recordedRequest{Method: r.Method, Host: r.Host, Path: r.URL.Path, Query: r.URL.RawQuery, Proto: r.Proto, TE: r.TransferEncoding, Header: r.Header.Clone()}
	sw := &statusRecorder{ResponseWriter: w, status: 200}
	defer func() {
		rec.Status = sw.status
		f.mu.Lock()
		f.seen = append(f.seen, rec)
		f.mu.Unlock()
	}()

	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch r.Host {
	case "github.com":
		if !f.authorized(r.Header.Get("Authorization"), segs[0], true) {
			sw.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			http.Error(sw, "credential required", http.StatusUnauthorized)
			return
		}
		f.serveGit(sw, r)
	default:
		var owner string
		if len(segs) >= 2 && segs[0] == "repos" {
			owner = segs[1]
		}
		if !f.authorized(r.Header.Get("Authorization"), owner, false) {
			http.Error(sw, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		rec.Body = string(body)
		f.serveAPI(sw, r, rec.Body)
	}
}

// authorized accepts the installation token of owner (any when owner is empty,
// as for /user and GraphQL, which carry no owner in the path).
func (f *fakeGitHub) authorized(auth, owner string, basic bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for o, tok := range f.tokens {
		if owner != "" && !strings.EqualFold(o, owner) {
			continue
		}
		want := "Bearer " + tok
		if basic {
			want = "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok))
		}
		if auth == want {
			return true
		}
	}
	return false
}

func (f *fakeGitHub) serveGit(w http.ResponseWriter, r *http.Request) {
	git, err := exec.LookPath("git")
	require.NoError(f.t, err)
	out, err := exec.Command(git, "--exec-path").Output()
	require.NoError(f.t, err)
	h := &cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(out)), "git-http-backend"),
		Env:  []string{"GIT_PROJECT_ROOT=" + f.root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=x-access-token", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + filepath.Join(f.root, "none.gitconfig")},
	}
	h.ServeHTTP(w, r)
}

func (f *fakeGitHub) serveAPI(w http.ResponseWriter, r *http.Request, body string) {
	w.Header().Set("Content-Type", "application/json")
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	pr := map[string]any{
		"id": "PR_1", "number": 7, "title": "Add feature", "state": "OPEN", "isDraft": true,
		"url": "https://github.com/acme/widgets/pull/7", "body": "from a sandbox",
		"headRefName": "feature", "baseRefName": "main", "author": map[string]any{"login": "keylatch-app"},
	}
	switch {
	case r.URL.Path == "/user":
		write(map[string]any{"login": "keylatch-app[bot]", "id": 1})
	case r.URL.Path == "/graphql":
		if strings.Contains(body, "createPullRequest") {
			f.mu.Lock()
			f.prCreated = true
			f.mu.Unlock()
			write(map[string]any{"data": map[string]any{"createPullRequest": map[string]any{"pullRequest": pr}}})
			return
		}
		f.mu.Lock()
		nodes := []any{}
		if f.prCreated {
			nodes = append(nodes, pr)
		}
		f.mu.Unlock()
		repo := map[string]any{
			"id": "R_1", "name": "widgets", "owner": map[string]any{"login": "acme"}, "nameWithOwner": "acme/widgets",
			"hasIssuesEnabled": true, "viewerPermission": "WRITE", "isPrivate": true, "isFork": false, "url": "https://github.com/acme/widgets",
			"defaultBranchRef": map[string]any{"name": "main"}, "mergeCommitAllowed": true, "squashMergeAllowed": true, "rebaseMergeAllowed": true,
			"pullRequest": pr, "pullRequests": map[string]any{"nodes": nodes, "totalCount": len(nodes)},
		}
		write(map[string]any{"data": map[string]any{"repository": repo, "viewer": map[string]any{"login": "keylatch-app[bot]"}}})
	case strings.HasPrefix(r.URL.Path, "/repos/"):
		write(map[string]any{"full_name": strings.TrimPrefix(r.URL.Path, "/repos/"), "default_branch": "main"})
	default:
		http.NotFound(w, r)
	}
}
