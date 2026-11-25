package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/proxy"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

// defaultProxyGitHubPermissions is what the proxy's token carries unless the
// connection's proxy.github.permissions says otherwise: push to branches and
// open or update pull requests.
var defaultProxyGitHubPermissions = map[string]string{
	"contents":      "write",
	"pull_requests": "write",
	"metadata":      "read",
}

// adminPermissions are the GitHub App permissions that can change access or
// settings; a listener must opt in with allow_admin_permissions to request
// them. Any permission at the admin level needs the opt-in too.
var adminPermissions = []string{
	"administration", "organization_administration", "members",
	"organization_custom_org_roles", "organization_custom_roles", "organization_custom_properties",
	"organization_secrets", "organization_self_hosted_runners",
	"organization_personal_access_tokens", "organization_personal_access_token_requests",
	"organization_copilot_seat_management",
}

func proxyCACertPath(lookup llmcontext.Lookup) string {
	return filepath.Join(paths.GatewayDir(lookup), "proxy-ca.pem")
}

func proxyCAKeyPath(lookup llmcontext.Lookup) string {
	return filepath.Join(paths.GatewayDir(lookup), "proxy-ca.key")
}

func proxyCallerTokenPath(lookup llmcontext.Lookup) string {
	return filepath.Join(paths.GatewayDir(lookup), "proxy-token")
}

// loadProxyCA loads or creates the proxy CA, name-constrained to the union of
// hosts. A proxy CA is never created without constraints.
func loadProxyCA(lookup llmcontext.Lookup, hosts []string) (*proxy.CA, error) {
	permitted, err := proxy.PermittedDNS(hosts)
	if err != nil {
		return nil, err
	}
	if len(permitted) == 0 {
		return nil, NewPolicyDeny("proxy: no proxy.github host is configured in the operator config, so there is nothing to constrain the CA to")
	}
	if err := os.MkdirAll(paths.GatewayDir(lookup), 0o700); err != nil {
		return nil, fmt.Errorf("proxy: gateway dir: %w", err)
	}
	return proxy.LoadOrCreateFileCA(proxyCACertPath(lookup), proxyCAKeyPath(lookup), permitted)
}

// configuredProxyHosts lists the hosts of every proxy.github entry.
func configuredProxyHosts(cfg config.Config) []string {
	var hosts []string
	for _, name := range slices.Sorted(maps.Keys(cfg.Connections)) {
		if cp := cfg.Connections[name]; cp.Proxy != nil {
			for _, e := range cp.Proxy.GitHub {
				h := e.Host
				if h == "" {
					h = proxy.DefaultGitHubHost
				}
				hosts = append(hosts, strings.ToLower(h))
			}
		}
	}
	return hosts
}

// ensureProxyCallerToken returns the token callers present in
// Proxy-Authorization, creating the file (mode 0600) on first use. A stable
// file lets an unattended proxy restart without re-provisioning the guest.
func ensureProxyCallerToken(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("proxy token: %w", err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("proxy token: %w", err)
		}
		tok := hex.EncodeToString(b)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, fs.ErrExist) {
			return ensureProxyCallerToken(path)
		}
		if err != nil {
			return "", fmt.Errorf("proxy token: %w", err)
		}
		_, werr := f.WriteString(tok + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = os.Remove(path)
			return "", fmt.Errorf("proxy token: %w", werr)
		}
		return tok, nil
	}
	if err != nil {
		return "", fmt.Errorf("proxy token: %w", err)
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("proxy token: %s must not be readable by group or others (chmod 600)", path)
	}
	tok := strings.TrimSpace(string(data))
	if len(tok) < 32 {
		return "", fmt.Errorf("proxy token: %s is too short; delete it to generate a new one", path)
	}
	return tok, nil
}

type installationResolved struct {
	Owner  string
	Repos  []string
	Perms  map[string]string
	Admin  bool
	Policy *config.GitHubAppMintPolicy
}

type proxyGitHubResolved struct {
	Host          string
	Installations []installationResolved
}

// proxyGitHubSettings validates a proxy listener and returns what to mint for
// each installation. An installation's repositories and permissions are its
// allowlist and ceiling; the connection's mint.github_app policy still
// supplies the deny list, caller kinds and token lifetime.
func proxyGitHubSettings(cfg config.Config, connection, listen string) (proxyGitHubResolved, error) {
	var entry *config.GitHubProxyPolicy
	if cp, ok := cfg.Connections[connection]; ok && cp.Proxy != nil {
		for i := range cp.Proxy.GitHub {
			if cp.Proxy.GitHub[i].Listen == listen {
				entry = &cp.Proxy.GitHub[i]
			}
		}
	}
	if entry == nil || len(entry.Installations) == 0 {
		return proxyGitHubResolved{}, NewPolicyDeny("gateway up: connection %q has no proxy.github listener %q with installations in the operator config", connection, listen)
	}
	mintPolicy := githubAppMintPolicy(cfg, connection)
	if mintPolicy == nil {
		return proxyGitHubResolved{}, NewPolicyDeny("gateway up: connection %q has no mint.github_app policy in the operator config; the proxy mints under its deny list and lifetime", connection)
	}
	host := strings.ToLower(entry.Host)
	if host == "" {
		host = proxy.DefaultGitHubHost
	}
	out := proxyGitHubResolved{Host: host}
	seen := map[string]bool{}
	for _, inst := range entry.Installations {
		r, err := resolveInstallation(inst, mintPolicy)
		if err != nil {
			return proxyGitHubResolved{}, err
		}
		if seen[r.Owner] {
			return proxyGitHubResolved{}, NewPolicyDeny("gateway up: proxy.github %s: owner %q is configured twice", listen, inst.Owner)
		}
		seen[r.Owner] = true
		out.Installations = append(out.Installations, r)
	}
	return out, nil
}

func resolveInstallation(inst config.GitHubInstallationPolicy, mintPolicy *config.GitHubAppMintPolicy) (installationResolved, error) {
	owner := strings.ToLower(inst.Owner)
	if _, _, err := mint.ParseRepository(owner + "/x"); err != nil {
		return installationResolved{}, NewPolicyDeny("gateway up: proxy.github installation owner %q is not an account login", inst.Owner)
	}
	if len(inst.Repositories) == 0 {
		return installationResolved{}, NewPolicyDeny("gateway up: proxy.github installation %q lists no repositories", inst.Owner)
	}
	perms := maps.Clone(inst.Permissions)
	if len(perms) == 0 {
		perms = maps.Clone(defaultProxyGitHubPermissions)
	}
	for k, v := range perms {
		if _, _, perr := mint.ParsePermission(k + "=" + v); perr != nil {
			return installationResolved{}, NewPolicyDeny("gateway up: proxy.github %s permissions: %v", inst.Owner, perr)
		}
		if (slices.Contains(adminPermissions, k) || v == "admin") && !inst.AllowAdminPermissions {
			return installationResolved{}, NewPolicyDeny("gateway up: proxy.github %s permissions: %s=%s needs \"allow_admin_permissions\": true on this installation", inst.Owner, k, v)
		}
	}
	derived := *mintPolicy
	derived.AllowRepos = append(slices.Clone(mintPolicy.AllowRepos), inst.Repositories...)
	derived.PermissionCeiling = maps.Clone(mintPolicy.PermissionCeiling)
	if derived.PermissionCeiling == nil {
		derived.PermissionCeiling = map[string]string{}
	}
	maps.Copy(derived.PermissionCeiling, perms)
	for _, r := range inst.Repositories {
		o, _, perr := mint.ParseRepository(r)
		if perr != nil {
			return installationResolved{}, NewPolicyDeny("gateway up: proxy.github %s repositories: %v", inst.Owner, perr)
		}
		if !strings.EqualFold(o, owner) {
			return installationResolved{}, NewPolicyDeny("gateway up: proxy.github installation %q lists %q, which belongs to another owner", inst.Owner, r)
		}
		if cerr := mint.CheckGitHubApp(&derived, mint.CallerService, mint.Request{Repository: r, Permissions: perms}); cerr != nil {
			return installationResolved{}, NewPolicyDeny("gateway up: mint policy refuses %s for the proxy: %v", r, cerr)
		}
	}
	return installationResolved{Owner: owner, Repos: slices.Clone(inst.Repositories), Perms: perms, Admin: inst.AllowAdminPermissions, Policy: &derived}, nil
}

type gitHubProxyParams struct {
	Connection   string
	Listen       string
	AllowSources []netip.Prefix
	Lookup       llmcontext.Lookup
	Config       config.Config
	Vault        gateway.VaultReader
	Audit        audit.Emitter
	// APIBase, HTTPClient and Upstream redirect GitHub; tests only.
	APIBase    string
	HTTPClient *http.Client
	Upstream   http.RoundTripper
}

// newGitHubProxy builds the intercepting proxy for one listener: one injector
// per installation, each with its own repositories, permissions and token.
func newGitHubProxy(p gitHubProxyParams) (*proxy.Server, error) {
	if err := validateGatewayListen(p.Listen); err != nil {
		return nil, NewUsageError("gateway up: --proxy-listen: %v", err)
	}
	if !connectionNameRE.MatchString(p.Connection) {
		return nil, NewUsageError("gateway up: --proxy-listen connection %q is not a connection name", p.Connection)
	}
	tmpl, terr := registry.Get(p.Connection)
	if terr != nil || !slices.ContainsFunc(tmpl.Capabilities, func(cp registry.Capability) bool { return cp.Name == mintCapability }) {
		return nil, NewUsageError("gateway up: --proxy-listen connection %q is not a connection type that can mint (use a github-app connection)", p.Connection)
	}
	if !isLoopbackListen(p.Listen) && len(p.AllowSources) == 0 {
		return nil, NewUsageError("gateway up: --proxy-listen %s is not loopback: --allow-source is required so the proxy is not reachable from other networks", p.Listen)
	}
	res, err := proxyGitHubSettings(p.Config, p.Connection, p.Listen)
	if err != nil {
		return nil, err
	}
	apiBase, err := proxy.GitHubAPIBase(res.Host)
	if err != nil {
		return nil, NewPolicyDeny("gateway up: proxy.github: %v", err)
	}
	if p.APIBase != "" {
		apiBase = p.APIBase
	}
	ca, err := loadProxyCA(p.Lookup, configuredProxyHosts(p.Config))
	if err != nil {
		return nil, err
	}
	callerToken, err := ensureProxyCallerToken(proxyCallerTokenPath(p.Lookup))
	if err != nil {
		return nil, err
	}

	var injectors []*proxy.GitHubInjector
	for _, inst := range res.Installations {
		inj, err := newInstallationInjector(p, res.Host, apiBase, tmpl.Category, inst)
		if err != nil {
			return nil, err
		}
		injectors = append(injectors, inj)
	}
	set, err := proxy.NewGitHubSet(injectors...)
	if err != nil {
		return nil, err
	}
	return &proxy.Server{
		Addr:              p.Listen,
		Profile:           proxy.ProxyProfile{Mode: "gateway_proxy", Hosts: set.Hosts()},
		CA:                ca,
		GitHub:            set,
		Token:             callerToken,
		AuditEmitter:      p.Audit,
		AllowNonLoopback:  len(p.AllowSources) > 0,
		SourceAllowed:     sourceAllowedFunc(p.AllowSources),
		UpstreamTransport: p.Upstream,
	}, nil
}

func newInstallationInjector(p gitHubProxyParams, host, apiBase, category string, inst installationResolved) (*proxy.GitHubInjector, error) {
	opts := &gateway.GitHubMintOptions{Connection: p.Connection, Namespace: "default", Category: category, Policy: inst.Policy, APIBase: apiBase, HTTPClient: p.HTTPClient}
	maxLife := mint.MaxLifetime(inst.Policy)
	minter := func(ctx context.Context) (string, time.Time, error) {
		ctx = audit.WithEmitter(ctx, p.Audit)
		strategy, err := gateway.NewGitHubAppStrategy(ctx, p.Vault, opts, inst.Repos[0])
		if err != nil {
			return "", time.Time{}, errors.New("the GitHub App credential is not available")
		}
		tok, err := strategy.MintScopedRepos(ctx, strategies.GitHubAppReposScope{Repositories: inst.Repos, Permissions: inst.Perms}, maxLife)
		if err != nil {
			return "", time.Time{}, errors.New("GitHub did not issue a matching token")
		}
		defer tok.Zero()
		return string(tok.Token), tok.ExpiresAt, nil
	}
	inj, err := proxy.NewGitHubInjector(host, inst.Repos, minter)
	if err != nil {
		return nil, err
	}
	permList := make([]string, 0, len(inst.Perms))
	for _, k := range slices.Sorted(maps.Keys(inst.Perms)) {
		permList = append(permList, k+"="+inst.Perms[k])
	}
	inj.OnMint = func(exp time.Time, err error) {
		extra := map[string]any{
			"connection":   p.Connection,
			"host":         host,
			"owner":        inst.Owner,
			"repositories": strings.Join(inst.Repos, ","),
			"permissions":  strings.Join(permList, ","),
			"caller_kind":  string(mint.CallerService),
			"via":          "proxy",
		}
		outcome := audit.OutcomeOK
		if err != nil {
			outcome, extra["reason"] = audit.OutcomeError, "mint_failed"
		} else {
			extra["expires_at"] = exp.UTC().Format(time.RFC3339)
		}
		_ = p.Audit.Emit(context.Background(), audit.Event{Timestamp: time.Now().UTC(), Action: audit.ActionMint, Outcome: outcome, RuntimeMode: "gateway_proxy", Extra: extra})
	}
	return inj, nil
}

type proxyListener struct{ Addr, Connection string }

// parseProxyListeners splits repeated --proxy-listen <addr>=<connection>
// values: an ad-hoc selection of the configured listeners to run.
func parseProxyListeners(values []string) ([]proxyListener, error) {
	var out []proxyListener
	seen := map[string]bool{}
	for _, v := range values {
		addr, conn, ok := strings.Cut(v, "=")
		if !ok || addr == "" || conn == "" {
			return nil, fmt.Errorf("--proxy-listen %q: use <ip:port>=<connection>", v)
		}
		if seen[addr] {
			return nil, fmt.Errorf("--proxy-listen %q is given twice", addr)
		}
		seen[addr] = true
		out = append(out, proxyListener{Addr: addr, Connection: conn})
	}
	return out, nil
}

func sourceAllowedFunc(prefixes []netip.Prefix) func(string) bool {
	if len(prefixes) == 0 {
		return nil
	}
	return func(remote string) bool { return gateway.SourceAllowed(prefixes, remote) }
}

func isLoopbackListen(addr string) bool {
	ap, err := netip.ParseAddrPort(addr)
	return err == nil && ap.Addr().IsLoopback()
}

func newProxyCACmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ca", Short: "The certificate authority guests trust for the GitHub proxy"}
	cmd.AddCommand(&cobra.Command{
		Use:   "print",
		Short: "Print the proxy CA certificate (PEM, no key); creates the CA on first use",
		Long: `Print the proxy CA certificate as PEM for a guest to trust. The private key stays on the
host (mode 0600) and is never printed. The certificate is name-constrained to the
hosts of the configured proxy.github entries (and their subdomains), so trusting it does not
let the proxy vouch for any other site.

In the guest, for example: keylatch proxy ca print > /usr/local/share/ca-certificates/keylatch-proxy.crt && update-ca-certificates`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := mintPolicyConfig()
			if err != nil {
				return NewPolicyDeny("proxy ca print: the operator config cannot be read: %v", err)
			}
			ca, err := loadProxyCA(llmcontext.DefaultLookup, configuredProxyHosts(cfg))
			if err != nil {
				return err
			}
			_, err = c.OutOrStdout().Write(ca.CertPEM())
			return err
		},
	})
	return cmd
}

func newProxyTokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "The token guests present to the GitHub proxy"}
	cmd.AddCommand(&cobra.Command{
		Use:   "print",
		Short: "Print the proxy caller token (created on first use); not available in an LLM session",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			lookup := llmcontext.DefaultLookup
			if llmcontext.IsLLMSession(lookup) {
				return NewSecurityBlock("proxy token print: refused in an LLM session; run it from your own shell")
			}
			tok, err := ensureProxyCallerToken(proxyCallerTokenPath(lookup))
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), tok)
			return nil
		},
	})
	return cmd
}
