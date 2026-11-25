package proxy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type routeKind int

const (
	kindNone routeKind = iota
	kindGit
	kindAPI
	kindGraphQL
	kindUploads
)

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// hostLayout says where a GitHub flavour serves git, REST, GraphQL and uploads.
//
//   - github.com: github.com, api.github.com (REST and /graphql), uploads.github.com.
//   - GHE.com data residency, SUBDOMAIN.ghe.com: SUBDOMAIN.ghe.com,
//     api.SUBDOMAIN.ghe.com, uploads.SUBDOMAIN.ghe.com.
//   - GitHub Enterprise Server HOST: everything on HOST; REST under /api/v3,
//     GraphQL at /api/graphql, uploads under /api/uploads.
type hostLayout struct {
	git, api, uploads string
	// single is true when one host serves git and the API under /api/.
	single bool
}

func newHostLayout(host string) (hostLayout, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		host = DefaultGitHubHost
	}
	if !hostRE.MatchString(host) {
		return hostLayout{}, fmt.Errorf("github proxy: host %q must be a DNS name such as github.com, octocorp.ghe.com or ghe.example.com", host)
	}
	switch {
	case host == DefaultGitHubHost:
		return hostLayout{git: host, api: "api." + host, uploads: "uploads." + host}, nil
	case strings.HasSuffix(host, ".ghe.com"):
		sub := strings.TrimSuffix(host, ".ghe.com")
		if strings.Contains(sub, ".") {
			return hostLayout{}, errors.New("github proxy: a ghe.com host is SUBDOMAIN.ghe.com (one label)")
		}
		return hostLayout{git: host, api: "api." + host, uploads: "uploads." + host}, nil
	}
	return hostLayout{git: host, single: true}, nil
}

func (l hostLayout) hosts() []string {
	if l.single {
		return []string{l.git}
	}
	return []string{l.git, l.api, l.uploads}
}

func (l hostLayout) apiBase() string {
	if l.single {
		return "https://" + l.git + "/api/v3"
	}
	return "https://" + l.api
}

// classify maps a request host and path to a route kind and the path the
// kind's rules apply to (the API prefix removed on a single-host server).
func (l hostLayout) classify(host, p string) (routeKind, string) {
	if l.single {
		if host != l.git {
			return kindNone, ""
		}
		switch {
		case p == "/api/v3" || strings.HasPrefix(p, "/api/v3/"):
			return kindAPI, "/" + strings.TrimPrefix(strings.TrimPrefix(p, "/api/v3"), "/")
		case p == "/api/graphql":
			return kindGraphQL, ""
		case strings.HasPrefix(p, "/api/uploads/"):
			return kindUploads, strings.TrimPrefix(p, "/api/uploads")
		case p == "/api" || strings.HasPrefix(p, "/api/"):
			return kindNone, ""
		}
		return kindGit, p
	}
	switch host {
	case l.git:
		return kindGit, p
	case l.api:
		if p == "/graphql" {
			return kindGraphQL, ""
		}
		return kindAPI, p
	case l.uploads:
		return kindUploads, p
	}
	return kindNone, ""
}

// PermittedDNS returns the DNS names a proxy CA must be constrained to for the
// listed hosts: each host itself, which also covers its api. and uploads.
// subdomains.
func PermittedDNS(hosts []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		l, err := newHostLayout(h)
		if err != nil {
			return nil, err
		}
		if !seen[l.git] {
			seen[l.git] = true
			out = append(out, l.git)
		}
	}
	return out, nil
}

// GitHubAPIBase is the REST API root for host (empty means github.com).
func GitHubAPIBase(host string) (string, error) {
	l, err := newHostLayout(host)
	if err != nil {
		return "", err
	}
	return l.apiBase(), nil
}
