package mintsession

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/registry"
)

// TokenField is the template field a minted installation token fills.
const TokenField = "token"

const (
	revokeTimeout = 3 * time.Second
	refreshMargin = 2 * time.Minute
)

// ErrUsage is wrapped when a request is malformed or incomplete.
var ErrUsage = errors.New("invalid mint session request")

// Config wires a Minter.
type Config struct {
	Store   connections.Store
	APIBase string
	// Policy returns the operator's configuration, which holds the mint policy.
	Policy func() (config.Config, error)
	// Audit receives one event per mint; sessions are refused without a
	// working audit log.
	Audit audit.Emitter
}

// Minter opens placeholder-backed GitHub App sessions.
type Minter struct{ cfg Config }

// New returns a Minter.
func New(cfg Config) *Minter { return &Minter{cfg: cfg} }

// Request describes one session.
type Request struct {
	Connection string
	Namespace  string
	// Repository is owner/name. Empty selects the policy's only allowed
	// repository.
	Repository string
	// Permissions are name=level pairs. Empty selects the policy's permission
	// ceiling.
	Permissions []string
	Caller      mint.CallerKind
}

// Open checks the request against the connection's mint policy and returns a
// credential that mints on first use. Nothing is read from the store and no
// token exists until a request needs one.
func (m *Minter) Open(ctx context.Context, req Request) (*Credential, error) {
	tmpl, err := registry.Get(req.Connection)
	if err != nil || !tmpl.IsMinted(TokenField) || !slices.ContainsFunc(tmpl.Capabilities, func(c registry.Capability) bool { return c.Name == "tokens.mint" }) {
		return nil, fmt.Errorf("%w: %q is not a connection type that mints tokens", ErrUsage, req.Connection)
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	cfg, err := m.cfg.Policy()
	if err != nil {
		return nil, fmt.Errorf("%w: the mint policy cannot be read: %v", mint.ErrDenied, err)
	}
	var policy *config.GitHubAppMintPolicy
	if cp, ok := cfg.Connections[req.Connection]; ok && cp.Mint != nil {
		policy = cp.Mint.GitHubApp
	}
	if policy == nil {
		return nil, fmt.Errorf("%w: the connection has no mint.github_app policy", mint.ErrDenied)
	}

	repo := req.Repository
	if repo == "" {
		if len(policy.AllowRepos) != 1 {
			return nil, fmt.Errorf("%w: name the repository with --repo owner/name", ErrUsage)
		}
		repo = policy.AllowRepos[0]
	}
	if _, _, err := mint.ParseRepository(repo); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	perms := maps.Clone(policy.PermissionCeiling)
	if len(req.Permissions) > 0 {
		perms = make(map[string]string, len(req.Permissions))
		for _, p := range req.Permissions {
			k, v, err := mint.ParsePermission(p)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrUsage, err)
			}
			if _, dup := perms[k]; dup {
				return nil, fmt.Errorf("%w: permission %s given more than once", ErrUsage, k)
			}
			perms[k] = v
		}
	}
	if len(perms) == 0 {
		return nil, fmt.Errorf("%w: name at least one permission", ErrUsage)
	}
	if err := mint.CheckGitHubAppPlaceholder(policy, req.Caller, mint.Request{Repository: repo, Permissions: perms}); err != nil {
		return nil, err
	}
	if err := audit.Ready(m.cfg.Audit); err != nil {
		return nil, fmt.Errorf("the audit log is not available (%v); Keylatch does not mint unaudited credentials", err)
	}
	return &Credential{
		cfg: m.cfg, category: tmpl.Category, connection: req.Connection, namespace: req.Namespace,
		repo: repo, perms: perms, caller: req.Caller, lifetime: mint.MaxLifetime(policy),
	}, nil
}

// Credential holds one session's minted installation token in memory only.
// It satisfies the placeholder package's Credential interface.
type Credential struct {
	cfg        Config
	category   string
	connection string
	namespace  string
	repo       string
	perms      map[string]string
	caller     mint.CallerKind
	lifetime   time.Duration

	mu      sync.Mutex
	token   []byte
	expires time.Time
	closed  bool
}

// Repository is the one repository the minted tokens cover.
func (c *Credential) Repository() string { return c.repo }

// Permissions are the permissions the minted tokens carry.
func (c *Credential) Permissions() map[string]string { return maps.Clone(c.perms) }

// Value returns a copy of the installation token, minting one on first use and
// again shortly before the cached token expires.
func (c *Credential) Value(ctx context.Context, field string) ([]byte, error) {
	if field != TokenField {
		return nil, fmt.Errorf("mint session has no field %q", field)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("mint session is closed")
	}
	if len(c.token) > 0 && time.Until(c.expires) > min(refreshMargin, c.lifetime/4) {
		return bytes.Clone(c.token), nil
	}
	clear(c.token)
	c.token = nil
	if err := c.mint(ctx); err != nil {
		return nil, err
	}
	return bytes.Clone(c.token), nil
}

func (c *Credential) mint(ctx context.Context) error {
	strategy, err := LoadGitHubApp(ctx, c.cfg.Store, c.namespace, c.category, c.connection, c.repo, c.cfg.APIBase)
	if err != nil {
		return err
	}
	event := AuditEvent{
		Connection: c.connection, Namespace: c.namespace, Repository: c.repo, Permissions: c.perms,
		Caller: c.caller, RuntimeMode: "placeholder",
	}
	tok, err := strategy.MintScoped(ctx, strategies.GitHubAppScope{Repository: c.repo, Permissions: c.perms}, c.lifetime)
	if err != nil {
		event.Outcome, event.Reason = audit.OutcomeError, "github_error"
		if errors.Is(err, strategies.ErrScopeMismatch) {
			event.Reason = "scope_mismatch"
		}
		_ = event.Emit(ctx, c.cfg.Audit)
		return err
	}
	event.Outcome, event.ExpiresAt = audit.OutcomeOK, tok.ExpiresAt
	if err := event.Emit(ctx, c.cfg.Audit); err != nil {
		if rerr := strategy.Revoke(ctx, tok.Token); rerr != nil {
			err = fmt.Errorf("%w; revoking the token failed: %v", err, rerr)
		}
		tok.Zero()
		return fmt.Errorf("the audit line could not be written: %w", err)
	}
	c.token, c.expires = tok.Token, tok.ExpiresAt
	return nil
}

// Close wipes the cached token and revokes it with GitHub.
func (c *Credential) Close() {
	c.mu.Lock()
	token := c.token
	c.token = nil
	c.closed = true
	c.mu.Unlock()
	if len(token) == 0 {
		return
	}
	defer clear(token)
	ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
	defer cancel()
	strategy := strategies.NewGitHubAppInstallationStrategy("", "", nil, strategies.WithGitHubAPIBase(c.cfg.APIBase))
	_ = strategy.Revoke(ctx, token)
}
