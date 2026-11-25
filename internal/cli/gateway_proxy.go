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

// proxyGitHubPermissionCeiling is every permission the proxy may be configured
// with and its highest level. administration is not on the list on purpose.
var proxyGitHubPermissionCeiling = map[string]string{
	"contents": "write", "pull_requests": "write", "metadata": "read",
	"actions": "read", "checks": "read", "issues": "write",
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

func loadProxyCA(lookup llmcontext.Lookup) (*proxy.CA, error) {
	if err := os.MkdirAll(paths.GatewayDir(lookup), 0o700); err != nil {
		return nil, fmt.Errorf("proxy: gateway dir: %w", err)
	}
	return proxy.LoadOrCreateFileCA(proxyCACertPath(lookup), proxyCAKeyPath(lookup), []string{proxy.GitHubHost})
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

// proxyGitHubSettings validates the connection's proxy.github policy against
// the operator's mint.github_app policy and returns what to mint.
func proxyGitHubSettings(cfg config.Config, connection, listen string) (repos []string, perms map[string]string, mintPolicy *config.GitHubAppMintPolicy, err error) {
	var entry *config.GitHubProxyPolicy
	if cp, ok := cfg.Connections[connection]; ok && cp.Proxy != nil {
		for i := range cp.Proxy.GitHub {
			if cp.Proxy.GitHub[i].Listen == listen {
				entry = &cp.Proxy.GitHub[i]
			}
		}
	}
	if entry == nil || len(entry.Repositories) == 0 {
		return nil, nil, nil, NewPolicyDeny("gateway up: connection %q has no proxy.github entry with listen %q and repositories in the operator config", connection, listen)
	}
	mintPolicy = githubAppMintPolicy(cfg, connection)
	if mintPolicy == nil {
		return nil, nil, nil, NewPolicyDeny("gateway up: connection %q has no mint.github_app policy in the operator config; the proxy mints under the same limits", connection)
	}
	perms = maps.Clone(entry.Permissions)
	if len(perms) == 0 {
		perms = maps.Clone(defaultProxyGitHubPermissions)
	}
	for k, v := range perms {
		top, known := proxyGitHubPermissionCeiling[k]
		if !known {
			return nil, nil, nil, NewPolicyDeny("gateway up: proxy.github.permissions: %q is not allowed (allowed: %s)", k, strings.Join(slices.Sorted(maps.Keys(proxyGitHubPermissionCeiling)), ", "))
		}
		if (v != "read" && v != "write") || (top == "read" && v != "read") {
			return nil, nil, nil, NewPolicyDeny("gateway up: proxy.github.permissions: %s may be at most %q", k, top)
		}
	}
	// The proxy's own repository list is the allowlist for this listener, so
	// it is not repeated in mint.github_app.allow_repos; the ceiling, deny
	// list, callers and lifetime still come from the mint policy.
	derived := *mintPolicy
	derived.AllowRepos = append(slices.Clone(mintPolicy.AllowRepos), entry.Repositories...)
	mintPolicy = &derived
	owner := ""
	for _, r := range entry.Repositories {
		o, _, perr := mint.ParseRepository(r)
		if perr != nil {
			return nil, nil, nil, NewPolicyDeny("gateway up: proxy.github.repositories: %v", perr)
		}
		if owner != "" && !strings.EqualFold(owner, o) {
			return nil, nil, nil, NewPolicyDeny("gateway up: proxy.github.repositories must share one owner (one installation); got %q and %q", owner, o)
		}
		owner = o
		if cerr := mint.CheckGitHubApp(mintPolicy, mint.CallerService, mint.Request{Repository: r, Permissions: perms}); cerr != nil {
			return nil, nil, nil, NewPolicyDeny("gateway up: mint policy refuses %s for the proxy: %v", r, cerr)
		}
	}
	return slices.Clone(entry.Repositories), perms, mintPolicy, nil
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

// newGitHubProxy builds the intercepting proxy that injects one minted
// installation token into git and API requests for the configured repositories.
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
	repos, perms, mintPolicy, err := proxyGitHubSettings(p.Config, p.Connection, p.Listen)
	if err != nil {
		return nil, err
	}
	opts := &gateway.GitHubMintOptions{Connection: p.Connection, Namespace: "default", Category: tmpl.Category, Policy: mintPolicy, APIBase: p.APIBase, HTTPClient: p.HTTPClient}
	ca, err := loadProxyCA(p.Lookup)
	if err != nil {
		return nil, err
	}
	callerToken, err := ensureProxyCallerToken(proxyCallerTokenPath(p.Lookup))
	if err != nil {
		return nil, err
	}

	maxLife := mint.MaxLifetime(mintPolicy)
	minter := func(ctx context.Context) (string, time.Time, error) {
		ctx = audit.WithEmitter(ctx, p.Audit)
		strategy, err := gateway.NewGitHubAppStrategy(ctx, p.Vault, opts, repos[0])
		if err != nil {
			return "", time.Time{}, errors.New("the GitHub App credential is not available")
		}
		tok, err := strategy.MintScopedRepos(ctx, strategies.GitHubAppReposScope{Repositories: repos, Permissions: perms}, maxLife)
		if err != nil {
			return "", time.Time{}, errors.New("GitHub did not issue a matching token")
		}
		defer tok.Zero()
		return string(tok.Token), tok.ExpiresAt, nil
	}
	inj, err := proxy.NewGitHubInjector(repos, minter)
	if err != nil {
		return nil, err
	}
	permList := make([]string, 0, len(perms))
	for _, k := range slices.Sorted(maps.Keys(perms)) {
		permList = append(permList, k+"="+perms[k])
	}
	inj.OnMint = func(exp time.Time, err error) {
		extra := map[string]any{
			"connection":   p.Connection,
			"repositories": strings.Join(repos, ","),
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

	return &proxy.Server{
		Addr:              p.Listen,
		Profile:           proxy.ProxyProfile{Mode: "gateway_proxy", Hosts: inj.Hosts()},
		CA:                ca,
		GitHub:            inj,
		Token:             callerToken,
		AuditEmitter:      p.Audit,
		AllowNonLoopback:  len(p.AllowSources) > 0,
		SourceAllowed:     sourceAllowedFunc(p.AllowSources),
		UpstreamTransport: p.Upstream,
	}, nil
}

// parseProxyListeners splits repeated --proxy-listen <addr>=<connection> values.
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

type proxyListener struct{ Addr, Connection string }

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
host (mode 0600) and is never printed. The certificate is name-constrained to github.com
and its subdomains, so trusting it does not let the proxy vouch for any other site.

In the guest, for example: keylatch proxy ca print > /usr/local/share/ca-certificates/keylatch-proxy.crt && update-ca-certificates`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			ca, err := loadProxyCA(llmcontext.DefaultLookup)
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
