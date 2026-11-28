package registry

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// AllowedProviderBaseURLs maps provider IDs to their allowed upstream hostnames.
// This list is validated at template install time (build-time) AND DNS-reverified
// at request time.
var AllowedProviderBaseURLs = map[string][]string{
	"openai":          {"api.openai.com"},
	"openrouter":      {"openrouter.ai"},
	"slack":           {"slack.com", "api.slack.com"},
	"google":          {"oauth2.googleapis.com", "www.googleapis.com", "accounts.google.com"},
	"microsoft":       {"login.microsoftonline.com", "graph.microsoft.com"},
	"github":          {"api.github.com", "github.com"},
	"dropbox":         {"api.dropboxapi.com"},
	"aws":             {"sts.amazonaws.com"},
	"hashicorp-vault": {}, // runtime-configured; validated separately
}

// AllowProviderHosts registers the upstream hosts of a user-defined provider so
// the gateway SSRF gate accepts them. Call it before the gateway starts: the
// allowlist is read without locking.
func AllowProviderHosts(provider string, hosts []string) {
	AllowedProviderBaseURLs[provider] = append([]string(nil), hosts...)
}

var exactHostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// allowEmbeddedTemplateHosts adds the hosts an embedded template declares (its
// secret-substitution hosts and its HTTPS test endpoint) to the allowlist,
// next to any hand-written entry. Entries with an empty list stay
// operator-configured. Call it before the gateway starts.
func allowEmbeddedTemplateHosts(t ConnectionTemplate) {
	declared := append([]string(nil), t.Hosts...)
	if u, err := url.Parse(t.TestStrategy.Endpoint); err == nil && u.Scheme == "https" {
		declared = append(declared, u.Host)
	}
	existing, known := AllowedProviderBaseURLs[t.Provider]
	if known && len(existing) == 0 {
		return
	}
	merged := slices.Clone(existing)
	for _, h := range declared {
		h = strings.ToLower(h)
		if exactHostname.MatchString(h) && !slices.Contains(merged, h) {
			merged = append(merged, h)
		}
	}
	if len(merged) == 0 || (known && len(merged) == len(existing)) {
		return
	}
	AllowedProviderBaseURLs[t.Provider] = merged
}

// SSRFDenyRanges contains all networks that upstream targets must not resolve to.
// Includes RFC 1918, link-local, loopback, CGN, multicast, and unspecified.
var SSRFDenyRanges []*net.IPNet

func init() {
	denyRangeStrings := []string{
		// Loopback.
		"127.0.0.0/8",
		"::1/128",
		// RFC 1918 private.
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// Link-local (IMDS on AWS/GCP/Azure lives here).
		"169.254.0.0/16",
		"fe80::/10",
		// CGN (RFC 6598).
		"100.64.0.0/10",
		// Multicast.
		"224.0.0.0/4",
		"ff00::/8",
		// Unspecified.
		"0.0.0.0/8",
		"::/128",
		// IPv6 unique local.
		"fc00::/7",
	}
	for _, cidr := range denyRangeStrings {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("ssrf: invalid deny range: " + cidr + ": " + err.Error())
		}
		SSRFDenyRanges = append(SSRFDenyRanges, ipNet)
	}
}

// ErrSSRFTargetForbidden is returned when a URL resolves to a denied network.
var ErrSSRFTargetForbidden = errors.New("ssrf: target host is forbidden")

// ValidateTemplateBaseURL validates that rawURL is safe for the given providerID.
// It checks:
//  1. The URL parses cleanly.
//  2. The provider has an allowlist entry (fail-closed — unknown providers are denied).
//  3. The host is in AllowedProviderBaseURLs[providerID] (if the list is non-empty).
//     Providers with empty allowlist (e.g. hashicorp-vault) skip the host-match check
//     but still require the DNS deny-list check.
//  4. All resolved IPs are not in SSRFDenyRanges.
func ValidateTemplateBaseURL(providerID, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("ssrf: invalid URL %q: %w", rawURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("ssrf: empty host in URL %q", rawURL)
	}

	// Fail-closed: unknown providers are denied entirely.
	allowed, ok := AllowedProviderBaseURLs[providerID]
	if !ok {
		return fmt.Errorf("%w: provider %q has no allowlist entry", ErrSSRFTargetForbidden, providerID)
	}

	// If allowlist is non-empty, host must be in it.
	if len(allowed) > 0 {
		if !hostInList(host, allowed) {
			return fmt.Errorf("ssrf: host %q is not in allowlist for provider %q: %w", host, providerID, ErrSSRFTargetForbidden)
		}
	}
	// len(allowed) == 0: operator-configured (e.g. hashicorp-vault) — any host allowed
	// but the DNS deny-list check below still applies unconditionally.

	// DNS-resolve and verify IPs against deny ranges.
	if err := verifyHostIPs(host); err != nil {
		return err
	}
	return nil
}

// hostInList returns true if host is in the list.
func hostInList(host string, list []string) bool {
	for _, h := range list {
		if h == host {
			return true
		}
	}
	return false
}

// verifyHostIPs resolves host to IPs and checks each against SSRFDenyRanges.
func verifyHostIPs(host string) error {
	// If host is already an IP literal, parse directly.
	if ip := net.ParseIP(host); ip != nil {
		return checkIP(ip)
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("ssrf: DNS lookup for %q failed: %w", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if err := checkIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// checkIP returns ErrSSRFTargetForbidden if ip falls in a deny range.
func checkIP(ip net.IP) error {
	for _, network := range SSRFDenyRanges {
		if network.Contains(ip) {
			return fmt.Errorf("ssrf: resolved IP %s is in deny range %s: %w", ip, network, ErrSSRFTargetForbidden)
		}
	}
	return nil
}
