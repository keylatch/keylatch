package proxy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Selection failures, answered with 407.
const (
	RefusalInstallationRequired = "installation_required"
	RefusalUnknownInstallation  = "unknown_installation"
)

// GitHubSet is the installations one proxy listener serves, keyed by GitHub
// account. The caller picks one with the Proxy-Authorization user name; each
// installation keeps its own repositories, permissions and token cache.
type GitHubSet struct {
	byOwner map[string]*GitHubInjector
	first   *GitHubInjector
}

// NewGitHubSet groups injectors that serve the same host and distinct owners.
func NewGitHubSet(injectors ...*GitHubInjector) (*GitHubSet, error) {
	if len(injectors) == 0 {
		return nil, errors.New("github proxy: a listener needs at least one installation")
	}
	set := &GitHubSet{byOwner: map[string]*GitHubInjector{}, first: injectors[0]}
	for _, in := range injectors {
		if !slices.Equal(in.Hosts(), set.first.Hosts()) {
			return nil, errors.New("github proxy: the installations of one listener must share a host")
		}
		if _, dup := set.byOwner[in.owner]; dup {
			return nil, fmt.Errorf("github proxy: owner %q is configured twice on one listener", in.owner)
		}
		set.byOwner[in.owner] = in
	}
	return set, nil
}

// Hosts is the host allowlist the listener needs.
func (s *GitHubSet) Hosts() []string { return s.first.Hosts() }

// IsGitHubHost reports whether host (no port) belongs to the listener.
func (s *GitHubSet) IsGitHubHost(host string) bool { return s.first.IsGitHubHost(host) }

// Select returns the installation for the Proxy-Authorization user name. An
// empty name (Bearer auth) selects the only installation when there is exactly
// one; an unknown name never falls back to another installation.
func (s *GitHubSet) Select(user string) (*GitHubInjector, string) {
	user = strings.ToLower(user)
	if user == "" {
		if len(s.byOwner) == 1 {
			return s.first, ""
		}
		return nil, RefusalInstallationRequired
	}
	if in, ok := s.byOwner[user]; ok {
		return in, ""
	}
	return nil, RefusalUnknownInstallation
}

type installationKey struct{}

func withInstallation(ctx context.Context, in *GitHubInjector) context.Context {
	return context.WithValue(ctx, installationKey{}, in)
}

func installationFrom(ctx context.Context) *GitHubInjector {
	in, _ := ctx.Value(installationKey{}).(*GitHubInjector)
	return in
}
