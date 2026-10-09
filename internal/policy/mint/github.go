// Package mint decides whether a scoped credential may be minted. Every
// check here runs before any key material is read.
package mint

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/config"
)

// CallerKind classifies who is asking for a mint.
type CallerKind string

// Caller kinds.
const (
	CallerAgent   CallerKind = "agent"
	CallerHuman   CallerKind = "human"
	CallerHost    CallerKind = "host"
	CallerService CallerKind = "service"
)

// MaxTTL is the ceiling for max_ttl and the default when it is unset.
const MaxTTL = time.Hour

// ErrDenied is wrapped by every policy refusal.
var ErrDenied = errors.New("mint denied by policy")

// ErrInvalidPolicy is wrapped when the configured policy itself is invalid.
var ErrInvalidPolicy = errors.New("invalid mint.github_app policy")

var (
	ownerRe      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	repoNameRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	permissionRe = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)
)

var levelRank = map[string]int{"read": 1, "write": 2, "admin": 3}

var defaultCallers = []CallerKind{CallerService, CallerHost}

// Request is one GitHub App mint request.
type Request struct {
	Repository  string // owner/name
	Permissions map[string]string
}

// ParseRepository validates an owner/name pair.
func ParseRepository(s string) (owner, name string, err error) {
	owner, name, ok := strings.Cut(s, "/")
	if !ok || !ownerRe.MatchString(owner) || !repoNameRe.MatchString(name) || name == "." || name == ".." {
		return "", "", fmt.Errorf("repository %q must be owner/name", s)
	}
	return owner, name, nil
}

// ParsePermission validates one k=v permission flag.
func ParsePermission(s string) (key, level string, err error) {
	key, level, ok := strings.Cut(s, "=")
	if !ok || !permissionRe.MatchString(key) {
		return "", "", fmt.Errorf("permission %q must be name=read|write|admin", s)
	}
	if _, known := levelRank[level]; !known {
		return "", "", fmt.Errorf("permission %q: level must be read, write or admin", s)
	}
	return key, level, nil
}

// Validate checks a policy for values that can never be honoured.
func Validate(p *config.GitHubAppMintPolicy) error {
	if p.MaxTTL < 0 || time.Duration(p.MaxTTL)*time.Second > MaxTTL {
		return fmt.Errorf("%w: max_ttl %d must be between 1 and %d seconds", ErrInvalidPolicy, p.MaxTTL, int(MaxTTL.Seconds()))
	}
	for _, c := range p.Callers {
		switch CallerKind(c) {
		case CallerService, CallerHost, CallerHuman:
		case CallerAgent:
			return fmt.Errorf("%w: agent sessions can never mint", ErrInvalidPolicy)
		default:
			return fmt.Errorf("%w: unknown caller kind %q", ErrInvalidPolicy, c)
		}
	}
	for k, v := range p.PermissionCeiling {
		if _, _, err := ParsePermission(k + "=" + v); err != nil {
			return fmt.Errorf("%w: permission_ceiling: %v", ErrInvalidPolicy, err)
		}
	}
	for _, r := range p.AllowRepos {
		if _, _, err := ParseRepository(r); err != nil {
			return fmt.Errorf("%w: allow_repos: %v", ErrInvalidPolicy, err)
		}
	}
	return nil
}

// MaxLifetime returns the policy's token lifetime ceiling.
func MaxLifetime(p *config.GitHubAppMintPolicy) time.Duration {
	if p.MaxTTL == 0 {
		return MaxTTL
	}
	return time.Duration(p.MaxTTL) * time.Second
}

// CheckGitHubApp applies, in order: the caller policy, the owner deny list
// (which wins over every allow), the owner and repository allowlists, and
// the permission ceiling. A nil policy denies.
func CheckGitHubApp(p *config.GitHubAppMintPolicy, caller CallerKind, req Request) error {
	if caller == CallerAgent {
		return fmt.Errorf("%w: agent sessions cannot mint", ErrDenied)
	}
	if p == nil {
		return fmt.Errorf("%w: the connection has no mint.github_app policy", ErrDenied)
	}
	if err := Validate(p); err != nil {
		return err
	}

	allowed := defaultCallers
	if len(p.Callers) > 0 {
		allowed = nil
		for _, c := range p.Callers {
			allowed = append(allowed, CallerKind(c))
		}
	}
	if !slices.Contains(allowed, caller) {
		return fmt.Errorf("%w: caller kind %q is not allowed to mint", ErrDenied, caller)
	}

	owner, _, err := ParseRepository(req.Repository)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if containsFold(p.DenyOwners, owner) {
		return fmt.Errorf("%w: owner %q is on the deny list", ErrDenied, owner)
	}
	if !containsFold(p.AllowOwners, owner) && !containsFold(p.AllowRepos, req.Repository) {
		return fmt.Errorf("%w: %q is not in allow_owners or allow_repos", ErrDenied, req.Repository)
	}

	if len(req.Permissions) == 0 {
		return fmt.Errorf("%w: at least one permission is required", ErrDenied)
	}
	for k, v := range req.Permissions {
		ceiling, ok := p.PermissionCeiling[k]
		if !ok {
			return fmt.Errorf("%w: permission %q is above the ceiling (not granted)", ErrDenied, k)
		}
		if levelRank[v] == 0 || levelRank[v] > levelRank[ceiling] {
			return fmt.Errorf("%w: permission %s=%s is above the ceiling %s=%s", ErrDenied, k, v, k, ceiling)
		}
	}
	return nil
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(v string) bool { return strings.EqualFold(v, s) })
}
