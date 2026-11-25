package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/spf13/cobra"
)

const restartHint = "restart the service to apply (systemd: systemctl --user restart keylatch-gateway.service; macOS: launchctl kickstart -k gui/$(id -u)/io.keylatch.gateway)"

func newGatewayConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show and edit what the gateway serves (listen, sources, mint, proxy listeners)",
		Long: `The gateway reads its settings from the operator config file: gateway.service
(listen, allow_source, allow_any_source, github_mint) and, per connection,
connections.<name>.proxy.github (one entry per proxy listener). 'gateway up' flags
override them for ad-hoc runs. Changing a setting needs a service restart, not a reinstall.`,
	}
	cmd.AddCommand(newGatewayConfigGetCmd(), newGatewayConfigSetCmd(), newGatewayConfigAddProxyCmd(), newGatewayConfigRemoveProxyCmd(), newGatewayConfigSetMintPolicyCmd())
	return cmd
}

func newGatewayConfigGetCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Print the effective settings (value-free)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := operatorConfig()
			if err != nil {
				return NewPolicyDeny("gateway config: the operator config cannot be read: %v", err)
			}
			info := buildGatewayInfo(cfg, settingsFromConfig(cfg), llmcontext.DefaultLookup)
			if asJSON {
				_, err := c.OutOrStdout().Write(info.json())
				return err
			}
			w := c.OutOrStdout()
			fmt.Fprintf(w, "listen:       %s\n", orNone(info.Listen))
			fmt.Fprintf(w, "allow_source: %s\n", orNone(strings.Join(info.AllowSource, ", ")))
			if info.AllowAnySource {
				fmt.Fprintln(w, "allow_any_source: true")
			}
			fmt.Fprintf(w, "github_mint:  %s\n", orNone(info.GitHubMint))
			if mp := info.GitHubMintPolicy; mp != nil {
				fmt.Fprintf(w, "mint policy (%s): allow_repos %s; allow_owners %s; deny_owners %s; ceiling %s; callers %s; max_ttl %s\n", info.GitHubMint,
					orNone(strings.Join(mp.AllowRepos, ",")), orNone(strings.Join(mp.AllowOwners, ",")), orNone(strings.Join(mp.DenyOwners, ",")),
					formatCeiling(mp.PermissionCeiling), strings.Join(mp.Callers, ","), time.Duration(mp.MaxTTL)*time.Second)
			}
			for _, p := range info.Proxies {
				fmt.Fprintf(w, "proxy %s: connection %s, host %s\n", p.Listen, p.Connection, p.Host)
				for _, in := range p.Installations {
					fmt.Fprintf(w, "  %s: %s\n", in.Owner, strings.Join(in.Repositories, ", "))
				}
			}
			if bad := invalidProxyEntries(cfg, info); len(bad) > 0 {
				fmt.Fprintf(w, "invalid proxy entries (not served): %s\n", strings.Join(bad, ", "))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func invalidProxyEntries(cfg config.Config, info gatewayInfo) []string {
	served := map[string]bool{}
	for _, p := range info.Proxies {
		served[p.Listen] = true
	}
	var bad []string
	for _, pl := range proxyListenersFromConfig(cfg) {
		if !served[pl.Addr] {
			bad = append(bad, pl.Addr)
		}
	}
	return bad
}

func newGatewayConfigSetCmd() *cobra.Command {
	var (
		listen, githubMint string
		sources            []string
		anySource          bool
	)
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set listen, allow-source, allow-any-source or github-mint (only the flags given change)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, path, err := operatorConfigForEdit()
			if err != nil {
				return NewPolicyDeny("gateway config: the operator config cannot be read: %v", err)
			}
			s := settingsFromConfig(cfg)
			if c.Flags().Changed("listen") {
				s.Listen = listen
			}
			if c.Flags().Changed("allow-source") {
				s.AllowSource = nil
				for _, v := range sources {
					if v != "" {
						s.AllowSource = append(s.AllowSource, v)
					}
				}
			}
			if c.Flags().Changed("allow-any-source") {
				s.AllowAnySource = anySource
			}
			if c.Flags().Changed("github-mint") {
				s.GitHubMint = githubMint
			}
			if err := storeGatewaySettings(&cfg, s); err != nil {
				return NewUsageError("gateway config set: %v", err)
			}
			if err := config.Save(path, cfg); err != nil {
				return fmt.Errorf("gateway config set: %w", err)
			}
			fmt.Fprintln(c.OutOrStdout(), "saved; "+restartHint)
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address:port to bind, an IP literal (empty clears it)")
	cmd.Flags().StringArrayVar(&sources, "allow-source", nil, "CIDR callers must come from, repeatable; replaces the list (an empty value clears it)")
	cmd.Flags().BoolVar(&anySource, "allow-any-source", false, "accept a non-loopback listen without allow-source")
	cmd.Flags().StringVar(&githubMint, "github-mint", "", "github-app connection POST /mint/github is served from (empty clears it)")
	return cmd
}

// storeGatewaySettings validates s and writes it into cfg's gateway.service.
func storeGatewaySettings(cfg *config.Config, s gatewaySettings) error {
	srcs, err := canonicalSources(s.AllowSource)
	if err != nil {
		return err
	}
	s.AllowSource = srcs
	if err := s.validate(); err != nil {
		return err
	}
	if cfg.Gateway == nil {
		cfg.Gateway = &config.GatewayConfig{}
	}
	if s.Listen == "" && len(s.AllowSource) == 0 && !s.AllowAnySource && s.GitHubMint == "" {
		cfg.Gateway.Service = nil
		return nil
	}
	cfg.Gateway.Service = &config.GatewayServiceConfig{Listen: s.Listen, AllowSource: s.AllowSource, AllowAnySource: s.AllowAnySource, GitHubMint: s.GitHubMint}
	return nil
}

func newGatewayConfigAddProxyCmd() *cobra.Command {
	var (
		connection, listen, host, owner string
		repos, perms                    []string
		admin                           bool
	)
	cmd := &cobra.Command{
		Use:   "add-proxy",
		Short: "Add or replace one installation on a proxy listener",
		Long: `Adds an installation (one GitHub account) to the proxy listener on --listen, creating the
listener under connections.<connection>.proxy.github[] when it does not exist and replacing the
installation of the same owner when it does. One listener serves several installations: callers
pick one with the Proxy-Authorization user name, the account login.

The installation mints one token for its repositories with the permissions (default
contents:write, pull_requests:write, metadata:read). Permissions are any GitHub App permission
name; administration and other administrative permissions need --allow-admin-permissions. If
the connection has no mint.github_app policy an empty one is created (deny list, callers and
lifetime stay at the defaults).`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := validateGatewayListen(listen); err != nil {
				return NewUsageError("gateway config add-proxy: --listen: %v", err)
			}
			if !connectionNameRE.MatchString(connection) {
				return NewUsageError("gateway config add-proxy: --connection %q is not a connection name", connection)
			}
			permMap := map[string]string{}
			for _, p := range perms {
				k, v, err := mint.ParsePermission(p)
				if err != nil {
					return NewUsageError("gateway config add-proxy: %v", err)
				}
				permMap[k] = v
			}
			cfg, path, err := operatorConfigForEdit()
			if err != nil {
				return NewPolicyDeny("gateway config: the operator config cannot be read: %v", err)
			}
			if cfg.Connections == nil {
				cfg.Connections = map[string]config.ConnectionPolicy{}
			}
			cp := cfg.Connections[connection]
			if cp.Mint == nil {
				cp.Mint = &config.MintPolicy{}
			}
			if cp.Mint.GitHubApp == nil {
				cp.Mint.GitHubApp = &config.GitHubAppMintPolicy{}
			}
			if cp.Proxy == nil {
				cp.Proxy = &config.ProxyPolicy{}
			}
			inst := config.GitHubInstallationPolicy{Owner: owner, Repositories: qualifyRepos(owner, repos), AllowAdminPermissions: admin}
			if len(permMap) > 0 {
				inst.Permissions = permMap
			}
			idx := slices.IndexFunc(cp.Proxy.GitHub, func(e config.GitHubProxyPolicy) bool { return e.Listen == listen })
			if idx < 0 {
				cp.Proxy.GitHub = append(cp.Proxy.GitHub, config.GitHubProxyPolicy{Listen: listen, Host: host})
				idx = len(cp.Proxy.GitHub) - 1
			}
			entry := &cp.Proxy.GitHub[idx]
			if c.Flags().Changed("host") {
				entry.Host = host
			}
			entry.Installations = slices.DeleteFunc(entry.Installations, func(i config.GitHubInstallationPolicy) bool { return strings.EqualFold(i.Owner, owner) })
			entry.Installations = append(entry.Installations, inst)
			cfg.Connections[connection] = cp
			if _, err := proxyGitHubSettings(cfg, connection, listen); err != nil {
				return err
			}
			if err := checkProxyEntryConflicts(cfg); err != nil {
				return NewUsageError("gateway config add-proxy: %v", err)
			}
			if err := config.Save(path, cfg); err != nil {
				return fmt.Errorf("gateway config add-proxy: %w", err)
			}
			fmt.Fprintln(c.OutOrStdout(), "saved. The proxy CA is constrained to the configured hosts: after adding a new host, `keylatch proxy ca print` reports a mismatch until you remove the proxy CA files and re-trust the new CA in guests. "+restartHint)
			return nil
		},
	}
	cmd.Flags().StringVar(&connection, "connection", "", "github-app connection to mint from (required)")
	cmd.Flags().StringVar(&listen, "listen", "", "address:port of the listener, an IP literal (required)")
	cmd.Flags().StringVar(&host, "host", "", "github.com (default), SUBDOMAIN.ghe.com, or a GitHub Enterprise Server hostname")
	cmd.Flags().StringVar(&owner, "owner", "", "GitHub account login of the installation (required)")
	cmd.Flags().StringArrayVar(&repos, "repo", nil, "repository name or owner/name the installation reaches, repeatable (required)")
	cmd.Flags().StringArrayVar(&perms, "permission", nil, "<name>=<read|write|admin>, repeatable (default contents=write pull_requests=write metadata=read)")
	cmd.Flags().BoolVar(&admin, "allow-admin-permissions", false, "allow administration and other administrative permissions on this installation")
	for _, f := range []string{"connection", "listen", "owner", "repo"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

// qualifyRepos turns bare names into owner/name.
func qualifyRepos(owner string, repos []string) []string {
	out := make([]string, 0, len(repos))
	for _, r := range repos {
		if !strings.Contains(r, "/") {
			r = owner + "/" + r
		}
		out = append(out, r)
	}
	return out
}

// checkProxyEntryConflicts refuses two listeners on one address.
func checkProxyEntryConflicts(cfg config.Config) error {
	seen := map[string]string{}
	for _, pl := range proxyListenersFromConfig(cfg) {
		if prev, dup := seen[pl.Addr]; dup {
			return fmt.Errorf("listen address %s is used by connections %s and %s", pl.Addr, prev, pl.Connection)
		}
		seen[pl.Addr] = pl.Connection
	}
	if s := settingsFromConfig(cfg); s.Listen != "" {
		if _, dup := seen[s.Listen]; dup {
			return fmt.Errorf("listen address %s is also the gateway's own", s.Listen)
		}
	}
	return nil
}

func newGatewayConfigRemoveProxyCmd() *cobra.Command {
	var listen, owner string
	cmd := &cobra.Command{
		Use:   "remove-proxy",
		Short: "Remove an installation from a proxy listener, or the whole listener",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, path, err := operatorConfigForEdit()
			if err != nil {
				return NewPolicyDeny("gateway config: the operator config cannot be read: %v", err)
			}
			removed := false
			for name, cp := range cfg.Connections {
				if cp.Proxy == nil {
					continue
				}
				var keep []config.GitHubProxyPolicy
				for _, e := range cp.Proxy.GitHub {
					if e.Listen != listen {
						keep = append(keep, e)
						continue
					}
					if owner == "" {
						removed = true
						continue
					}
					n := len(e.Installations)
					e.Installations = slices.DeleteFunc(e.Installations, func(i config.GitHubInstallationPolicy) bool { return strings.EqualFold(i.Owner, owner) })
					removed = removed || len(e.Installations) != n
					if len(e.Installations) > 0 {
						keep = append(keep, e)
					}
				}
				cp.Proxy.GitHub = keep
				if len(keep) == 0 {
					cp.Proxy = nil
				}
				cfg.Connections[name] = cp
			}
			if !removed {
				return NewUsageError("gateway config remove-proxy: nothing matches %s %s", listen, owner)
			}
			if err := config.Save(path, cfg); err != nil {
				return fmt.Errorf("gateway config remove-proxy: %w", err)
			}
			fmt.Fprintln(c.OutOrStdout(), "saved; "+restartHint)
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address:port of the listener (required)")
	cmd.Flags().StringVar(&owner, "owner", "", "remove only this account's installation (default: the whole listener)")
	_ = cmd.MarkFlagRequired("listen")
	return cmd
}

func formatCeiling(c map[string]string) string {
	parts := make([]string, 0, len(c))
	for _, k := range slices.Sorted(maps.Keys(c)) {
		parts = append(parts, k+":"+c[k])
	}
	return strings.Join(parts, ",")
}

func newGatewayConfigSetMintPolicyCmd() *cobra.Command {
	var (
		connection, maxTTL                                    string
		allowRepos, allowOwners, denyOwners, ceiling, callers []string
	)
	cmd := &cobra.Command{
		Use:   "set-mint-policy",
		Short: "Edit the mint.github_app policy of a connection (only the flags given change)",
		Long: `Edits connections.<connection>.mint.github_app, the policy POST /mint/github and
'keylatch mint' apply: which repositories may be minted (--allow-repo owner/name; --allow-owner,
--deny-owner by account), the permission ceiling (--permission-ceiling name=read|write|admin;
default contents:write, pull_requests:write, metadata:read when none is set), the caller kinds
(service, host, human; default service and host) and the longest token lifetime (--max-ttl,
1s to 1h). Each list flag replaces its list; an empty value clears it. The policy is created
when the connection has none. The 'administration' permission is never minted by the gateway.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if !connectionNameRE.MatchString(connection) {
				return NewUsageError("gateway config set-mint-policy: --connection %q is not a connection name", connection)
			}
			cfg, path, err := operatorConfigForEdit()
			if err != nil {
				return NewPolicyDeny("gateway config: the operator config cannot be read: %v", err)
			}
			if cfg.Connections == nil {
				cfg.Connections = map[string]config.ConnectionPolicy{}
			}
			cp := cfg.Connections[connection]
			if cp.Mint == nil {
				cp.Mint = &config.MintPolicy{}
			}
			pol := cp.Mint.GitHubApp
			if pol == nil {
				pol = &config.GitHubAppMintPolicy{}
			}
			next := *pol
			list := func(in []string) []string {
				var out []string
				for _, v := range in {
					if v != "" {
						out = append(out, v)
					}
				}
				return out
			}
			if c.Flags().Changed("allow-repo") {
				next.AllowRepos = list(allowRepos)
			}
			if c.Flags().Changed("allow-owner") {
				next.AllowOwners = list(allowOwners)
			}
			if c.Flags().Changed("deny-owner") {
				next.DenyOwners = list(denyOwners)
			}
			if c.Flags().Changed("caller") {
				next.Callers = list(callers)
			}
			for _, o := range append(slices.Clone(next.AllowOwners), next.DenyOwners...) {
				if _, _, err := mint.ParseRepository(o + "/x"); err != nil {
					return NewUsageError("gateway config set-mint-policy: owner %q is not an account login", o)
				}
			}
			if c.Flags().Changed("permission-ceiling") {
				next.PermissionCeiling = nil
				for _, v := range list(ceiling) {
					k, lvl, err := mint.ParsePermission(v)
					if err != nil {
						return NewUsageError("gateway config set-mint-policy: --permission-ceiling: %v", err)
					}
					if next.PermissionCeiling == nil {
						next.PermissionCeiling = map[string]string{}
					}
					next.PermissionCeiling[k] = lvl
				}
			}
			if c.Flags().Changed("max-ttl") {
				next.MaxTTL = 0
				if maxTTL != "" {
					d, err := time.ParseDuration(maxTTL)
					if err != nil || d < time.Second || d > mint.MaxTTL {
						return NewUsageError("gateway config set-mint-policy: --max-ttl %q must be a duration from 1s to 1h", maxTTL)
					}
					next.MaxTTL = int(d / time.Second)
				}
			}
			if err := mint.Validate(&next); err != nil {
				return NewUsageError("gateway config set-mint-policy: %v", err)
			}
			cp.Mint.GitHubApp = &next
			cfg.Connections[connection] = cp
			if err := config.Save(path, cfg); err != nil {
				return fmt.Errorf("gateway config set-mint-policy: %w", err)
			}
			fmt.Fprintln(c.OutOrStdout(), "saved; "+restartHint)
			return nil
		},
	}
	cmd.Flags().StringVar(&connection, "connection", "", "github-app connection whose policy to edit (required)")
	cmd.Flags().StringArrayVar(&allowRepos, "allow-repo", nil, "owner/name that may be minted, repeatable; replaces the list (an empty value clears it)")
	cmd.Flags().StringArrayVar(&allowOwners, "allow-owner", nil, "account whose repositories may all be minted, repeatable; replaces the list")
	cmd.Flags().StringArrayVar(&denyOwners, "deny-owner", nil, "account that may never be minted, repeatable; replaces the list")
	cmd.Flags().StringArrayVar(&ceiling, "permission-ceiling", nil, "<name>=<read|write|admin>, repeatable; replaces the ceiling (an empty value restores the default)")
	cmd.Flags().StringArrayVar(&callers, "caller", nil, "caller kind allowed to mint (service, host, human), repeatable; replaces the list")
	cmd.Flags().StringVar(&maxTTL, "max-ttl", "", "longest token lifetime, 1s to 1h, for example 30m (empty restores 1h)")
	_ = cmd.MarkFlagRequired("connection")
	return cmd
}
