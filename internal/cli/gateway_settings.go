package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/mint"
	"github.com/keylatch/keylatch/internal/version"
)

// gatewaySettings is what `gateway up` serves: the operator config, overridden
// by command-line flags for ad-hoc runs.
type gatewaySettings struct {
	Listen         string
	AllowSource    []string
	AllowAnySource bool
	GitHubMint     string
}

func settingsFromConfig(cfg config.Config) gatewaySettings {
	if cfg.Gateway == nil || cfg.Gateway.Service == nil {
		return gatewaySettings{}
	}
	s := cfg.Gateway.Service
	return gatewaySettings{Listen: s.Listen, AllowSource: slices.Clone(s.AllowSource), AllowAnySource: s.AllowAnySource, GitHubMint: s.GitHubMint}
}

// validate refuses settings that would expose the gateway or that no service
// could honour: a wildcard or hostname listen, bad CIDRs, a non-loopback
// listen without a source allowlist (unless explicitly open), bad names.
func (s gatewaySettings) validate() error {
	if s.AllowAnySource && len(s.AllowSource) > 0 {
		return errors.New("allow_any_source cannot be combined with allow_source")
	}
	if _, err := gateway.ParseAllowSources(s.AllowSource); err != nil {
		return err
	}
	if s.GitHubMint != "" && !connectionNameRE.MatchString(s.GitHubMint) {
		return fmt.Errorf("github_mint %q: connection names use letters, digits, '.', '_' and '-'", s.GitHubMint)
	}
	if s.Listen == "" {
		return nil
	}
	if err := validateGatewayListen(s.Listen); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(s.Listen)
	if !net.ParseIP(host).IsLoopback() && len(s.AllowSource) == 0 && !s.AllowAnySource {
		return fmt.Errorf("listen address %q is not loopback: pass --allow-source <CIDR> (config allow_source, for example the VM network) or, to accept any caller that can reach it, --allow-any-source (allow_any_source)", s.Listen)
	}
	return nil
}

// canonicalSources returns the CIDRs masked, the form the gateway compares.
func canonicalSources(in []string) ([]string, error) {
	prefixes, err := gateway.ParseAllowSources(in)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out, nil
}

// operatorConfigForEdit loads the operator config for modification; a missing
// file starts from the defaults.
func operatorConfigForEdit() (config.Config, string, error) {
	home, err := operatorHome()
	if err != nil {
		return config.Config{}, "", err
	}
	path := paths.DefaultConfig(home)
	cfg, err := operatorConfig()
	if err != nil {
		return config.Config{}, "", err
	}
	if cfg.Version == 0 {
		d := config.Default()
		d.Connections = cfg.Connections
		cfg = d
	}
	return cfg, path, nil
}

// proxyListenersFromConfig lists every configured proxy listener.
func proxyListenersFromConfig(cfg config.Config) []proxyListener {
	var out []proxyListener
	for _, name := range slices.Sorted(maps.Keys(cfg.Connections)) {
		if cp := cfg.Connections[name]; cp.Proxy != nil {
			for _, e := range cp.Proxy.GitHub {
				out = append(out, proxyListener{Addr: e.Listen, Connection: name})
			}
		}
	}
	return out
}

// gatewayInfo is the value-free description of the effective settings served
// by `gateway status --json` and GET /info. It holds no token, key, secret
// file path or vault reference.
type gatewayInfo struct {
	Schema         int      `json:"schema"`
	Version        string   `json:"version"`
	Listen         string   `json:"listen"`
	AllowSource    []string `json:"allow_source"`
	AllowAnySource bool     `json:"allow_any_source"`
	GitHubMint     string   `json:"github_mint"`
	// GitHubMintPolicy is the effective mint.github_app policy of the
	// github_mint connection (null without a connection or a policy). Additive
	// to schema 1.
	GitHubMintPolicy *mintPolicyInfo `json:"github_mint_policy"`
	Proxies          []proxyInfo     `json:"proxies"`
	CA               *caInfo         `json:"ca,omitempty"`
}

// mintPolicyInfo lists the effective limits of POST /mint/github: the default
// ceiling and callers are shown when the policy sets none. MaxTTL is seconds.
type mintPolicyInfo struct {
	AllowRepos        []string          `json:"allow_repos"`
	AllowOwners       []string          `json:"allow_owners"`
	DenyOwners        []string          `json:"deny_owners"`
	PermissionCeiling map[string]string `json:"permission_ceiling"`
	Callers           []string          `json:"callers"`
	MaxTTL            int               `json:"max_ttl"`
}

func mintPolicyInfoFor(cfg config.Config, connection string) *mintPolicyInfo {
	cp, ok := cfg.Connections[connection]
	if connection == "" || !ok || cp.Mint == nil || cp.Mint.GitHubApp == nil {
		return nil
	}
	p := cp.Mint.GitHubApp
	return &mintPolicyInfo{
		AllowRepos: append([]string{}, p.AllowRepos...), AllowOwners: append([]string{}, p.AllowOwners...), DenyOwners: append([]string{}, p.DenyOwners...),
		PermissionCeiling: mint.EffectiveCeiling(p), Callers: mint.EffectiveCallers(p), MaxTTL: int(mint.MaxLifetime(p).Seconds()),
	}
}

type proxyInfo struct {
	Listen        string             `json:"listen"`
	Host          string             `json:"host"`
	Connection    string             `json:"connection"`
	Installations []installationInfo `json:"installations"`
}

type installationInfo struct {
	Owner                 string            `json:"owner"`
	Repositories          []string          `json:"repositories"`
	Permissions           map[string]string `json:"permissions"`
	AllowAdminPermissions bool              `json:"allow_admin_permissions"`
}

type caInfo struct {
	SHA256 string `json:"sha256"`
	PEM    string `json:"pem"`
}

// buildGatewayInfo describes cfg with the flag overrides already applied in
// settings. The CA is read from its public certificate file when present.
func buildGatewayInfo(cfg config.Config, settings gatewaySettings, lookup llmcontext.Lookup) gatewayInfo {
	info := gatewayInfo{
		Schema: 1, Version: version.Version,
		Listen: settings.Listen, AllowSource: append([]string{}, settings.AllowSource...),
		AllowAnySource: settings.AllowAnySource, GitHubMint: settings.GitHubMint,
		Proxies: []proxyInfo{},
	}
	info.GitHubMintPolicy = mintPolicyInfoFor(cfg, settings.GitHubMint)
	for _, pl := range proxyListenersFromConfig(cfg) {
		r, err := proxyGitHubSettings(cfg, pl.Connection, pl.Addr)
		if err != nil {
			continue // invalid entries are reported by `gateway config get`, not served
		}
		pi := proxyInfo{Listen: pl.Addr, Host: r.Host, Connection: pl.Connection, Installations: []installationInfo{}}
		for _, in := range r.Installations {
			pi.Installations = append(pi.Installations, installationInfo{Owner: in.Owner, Repositories: in.Repos, Permissions: maps.Clone(in.Perms), AllowAdminPermissions: in.Admin})
		}
		info.Proxies = append(info.Proxies, pi)
	}
	if data, err := os.ReadFile(filepath.Join(paths.GatewayDir(lookup), filepath.Base(proxyCACertPath(lookup)))); err == nil {
		if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				sum := sha256.Sum256(cert.Raw)
				info.CA = &caInfo{SHA256: hex.EncodeToString(sum[:]), PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))}
			}
		}
	}
	return info
}

func (i gatewayInfo) json() []byte {
	b, _ := json.MarshalIndent(i, "", "  ")
	return append(b, '\n')
}

// gatewaySettingsFlags are the setting flags shared by the installers. They
// overlay the operator config; `install` writes the overlay back to it.
type gatewaySettingsFlags struct {
	listen, githubMint string
	sources            []string
	anySource          bool
}

func (f *gatewaySettingsFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.listen, "listen", "", "gateway address:port, an IP literal on the network the callers are on; written to the operator config (gateway.service.listen)")
	cmd.Flags().StringArrayVar(&f.sources, "allow-source", nil, "CIDR callers must come from, repeatable; written to the operator config (required for a non-loopback listen)")
	cmd.Flags().BoolVar(&f.anySource, "allow-any-source", false, "accept a non-loopback listen without allow-source")
	cmd.Flags().StringVar(&f.githubMint, "github-mint", "", "github-app connection to serve POST /mint/github from; written to the operator config")
}

func (f *gatewaySettingsFlags) changed(c *cobra.Command) bool {
	for _, n := range []string{"listen", "allow-source", "allow-any-source", "github-mint"} {
		if c.Flags().Changed(n) {
			return true
		}
	}
	return false
}

// effective is the operator config with the changed flags laid over it,
// validated when any flag was given.
func (f *gatewaySettingsFlags) effective(c *cobra.Command) (gatewaySettings, config.Config, string, error) {
	cfg, path, err := operatorConfigForEdit()
	if err != nil {
		return gatewaySettings{}, cfg, "", NewPolicyDeny("the operator config cannot be read: %v", err)
	}
	s := settingsFromConfig(cfg)
	if c.Flags().Changed("listen") {
		s.Listen = f.listen
	}
	if c.Flags().Changed("allow-source") {
		s.AllowSource = slices.Clone(f.sources)
	}
	if c.Flags().Changed("allow-any-source") {
		s.AllowAnySource = f.anySource
	}
	if c.Flags().Changed("github-mint") {
		s.GitHubMint = f.githubMint
	}
	if f.changed(c) {
		if err := storeGatewaySettings(&cfg, s); err != nil {
			return gatewaySettings{}, cfg, "", NewUsageError("%v", err)
		}
	}
	return s, cfg, path, nil
}

// persist writes the flags into the operator config when any was given.
func (f *gatewaySettingsFlags) persist(c *cobra.Command) error {
	if !f.changed(c) {
		return nil
	}
	_, cfg, path, err := f.effective(c)
	if err != nil {
		return err
	}
	if err := config.Save(path, cfg); err != nil {
		return fmt.Errorf("write the gateway settings: %w", err)
	}
	fmt.Fprintf(c.OutOrStdout(), "wrote gateway settings to %s\n", path)
	return nil
}
