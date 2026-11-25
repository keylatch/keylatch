package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultGitHubHost is the host a listener serves when none is configured.
const DefaultGitHubHost = "github.com"

// Refusal codes returned in the proxy's 403 JSON body.
const (
	RefusalRepository = "repository_not_allowed"
	RefusalOwner      = "owner_mismatch"
	RefusalRoute      = "route_not_allowed"
)

const (
	defaultRefreshBefore = 5 * time.Minute
	defaultRemintGap     = 30 * time.Second
	mintFailureBackoff   = 5 * time.Second
)

var errRemintTooSoon = errors.New("github token was minted moments ago; not minting again")

// TokenMinter mints one installation token. The injector never inspects how.
type TokenMinter func(ctx context.Context) (token string, expiresAt time.Time, err error)

// GitHubInjector decides which GitHub requests the proxy may forward and holds
// the one installation token injected into them. It mints lazily, caches the
// token in memory only, re-mints shortly before expiry, and re-mints on demand
// after an upstream 401, never more often than every 30 seconds.
type GitHubInjector struct {
	layout hostLayout
	owner  string              // lower-case account the installation belongs to
	repos  map[string]struct{} // lower-case owner/name
	mint   TokenMinter

	// OnMint, when set, is called after every mint attempt; it must not log
	// the token (it does not receive it).
	OnMint func(expiresAt time.Time, err error)

	now           func() time.Time
	refreshBefore time.Duration
	remintGap     time.Duration

	mu         sync.Mutex
	token      string
	expiresAt  time.Time
	mintedAt   time.Time
	failedAt   time.Time
	failureErr error
}

// NewGitHubInjector validates host (empty means github.com; also GitHub
// Enterprise Server HOST or SUBDOMAIN.ghe.com) and repos (owner/name) and
// returns the injector.
func NewGitHubInjector(host string, repos []string, mint TokenMinter) (*GitHubInjector, error) {
	layout, err := newHostLayout(host)
	if err != nil {
		return nil, err
	}
	if len(repos) == 0 {
		return nil, errors.New("github proxy: repositories must list at least one owner/name")
	}
	if mint == nil {
		return nil, errors.New("github proxy: no token minter")
	}
	g := &GitHubInjector{layout: layout, repos: map[string]struct{}{}, mint: mint, now: time.Now, refreshBefore: defaultRefreshBefore, remintGap: defaultRemintGap}
	for _, r := range repos {
		owner, name, ok := strings.Cut(r, "/")
		if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
			return nil, fmt.Errorf("github proxy: repository %q is not owner/name", r)
		}
		if g.owner != "" && !strings.EqualFold(g.owner, owner) {
			return nil, errors.New("github proxy: one installation serves one owner; repositories name several")
		}
		g.owner = strings.ToLower(owner)
		g.repos[strings.ToLower(r)] = struct{}{}
	}
	return g, nil
}

// Hosts is the host allowlist the proxy needs for this injector.
func (g *GitHubInjector) Hosts() []string { return g.layout.hosts() }

// IsGitHubHost reports whether host (no port) is served by the injector.
func (g *GitHubInjector) IsGitHubHost(host string) bool {
	return slices.Contains(g.layout.hosts(), strings.ToLower(host))
}

// APIBase is the REST API root of the configured host, where App tokens are minted.
func (g *GitHubInjector) APIBase() string { return g.layout.apiBase() }

// Owner is the account this installation belongs to (lower case).
func (g *GitHubInjector) Owner() string { return g.owner }

func (g *GitHubInjector) repoAllowed(owner, name string) bool {
	_, ok := g.repos[strings.ToLower(owner+"/"+strings.TrimSuffix(name, ".git"))]
	return ok
}

// Authorize decides one request. It returns the Authorization header value
// scheme ("basic" for git, "bearer" for the API hosts) or a refusal code. It
// performs no network I/O and never needs the token.
func (g *GitHubInjector) Authorize(host, method string, u *url.URL) (scheme, refusal string) {
	p := u.Path
	// A raw path that differs from the decoded one could be read differently
	// by the server than by this check (%2F, %2e%2e), so it is never forwarded.
	if u.RawPath != "" || p == "" || p[0] != '/' || strings.Contains(p, "//") || (p != "/" && path.Clean(p) != strings.TrimSuffix(p, "/")) {
		return "", RefusalRoute
	}
	switch kind, rest := g.layout.classify(strings.ToLower(host), p); kind {
	case kindGit:
		return g.authorizeGit(method, rest)
	case kindAPI:
		return g.authorizeAPI(rest)
	case kindGraphQL:
		return "bearer", ""
	case kindUploads:
		return g.authorizeUploads(rest)
	}
	return "", RefusalRoute
}

func splitPath(p string) []string { return strings.Split(strings.Trim(p, "/"), "/") }

func (g *GitHubInjector) authorizeGit(method, p string) (string, string) {
	segs := splitPath(p)
	if len(segs) >= 2 && !strings.EqualFold(segs[0], g.owner) {
		return "", RefusalOwner
	}
	if len(segs) >= 2 && !g.repoAllowed(segs[0], segs[1]) {
		return "", RefusalRepository
	}
	if len(segs) < 3 {
		return "", RefusalRoute
	}
	switch rest := strings.Join(segs[2:], "/"); {
	case rest == "info/refs" && (method == "GET" || method == "HEAD"):
	case (rest == "git-upload-pack" || rest == "git-receive-pack") && method == "POST":
	default:
		return "", RefusalRoute
	}
	return "basic", ""
}

func (g *GitHubInjector) authorizeAPI(p string) (string, string) {
	segs := splitPath(p)
	switch strings.ToLower(segs[0]) {
	case "repos":
		if len(segs) >= 2 && !strings.EqualFold(segs[1], g.owner) {
			return "", RefusalOwner
		}
		if len(segs) < 3 || !g.repoAllowed(segs[1], segs[2]) {
			return "", RefusalRepository
		}
	case "app", "installation", "applications":
		// These manage or revoke the installation token itself.
		return "", RefusalRoute
	}
	return "bearer", ""
}

func (g *GitHubInjector) authorizeUploads(p string) (string, string) {
	segs := splitPath(p)
	if strings.ToLower(segs[0]) == "repos" && len(segs) >= 2 && !strings.EqualFold(segs[1], g.owner) {
		return "", RefusalOwner
	}
	if strings.ToLower(segs[0]) != "repos" || len(segs) < 3 || !g.repoAllowed(segs[1], segs[2]) {
		return "", RefusalRepository
	}
	return "bearer", ""
}

// HeaderValue renders the Authorization header for scheme.
func HeaderValue(scheme, token string) string {
	if scheme == "basic" {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	}
	return "Bearer " + token
}

// Token returns the cached token, minting a new one when none is cached or it
// expires within the refresh window.
func (g *GitHubInjector) Token(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && g.now().Add(g.refreshBefore).Before(g.expiresAt) {
		return g.token, nil
	}
	return g.mintLocked(ctx)
}

// Refresh replaces rejected (a token upstream answered 401 to). When another
// request already replaced it, the current token is returned. A token minted
// less than 30 seconds ago is not replaced, so a caller that gets 401 for its
// own reasons cannot make the proxy mint in a loop.
func (g *GitHubInjector) Refresh(ctx context.Context, rejected string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && g.token != rejected {
		return g.token, nil
	}
	if !g.mintedAt.IsZero() && g.now().Sub(g.mintedAt) < g.remintGap {
		return "", errRemintTooSoon
	}
	return g.mintLocked(ctx)
}

func (g *GitHubInjector) mintLocked(ctx context.Context) (string, error) {
	if !g.failedAt.IsZero() && g.now().Sub(g.failedAt) < mintFailureBackoff {
		return "", g.failureErr
	}
	tok, exp, err := g.mint(ctx)
	if g.OnMint != nil {
		g.OnMint(exp, err)
	}
	if err != nil || tok == "" {
		if err == nil {
			err = errors.New("github proxy: minter returned no token")
		}
		g.token, g.failedAt, g.failureErr = "", g.now(), err
		return "", err
	}
	g.token, g.expiresAt, g.mintedAt, g.failedAt, g.failureErr = tok, exp, g.now(), time.Time{}, nil
	return tok, nil
}
