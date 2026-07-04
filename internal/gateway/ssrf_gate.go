package gateway

import (
	"fmt"
	"net"

	"github.com/keylatch/keylatch/internal/registry"
)

// ErrSSRFTargetForbidden is the sentinel for SSRF policy violations.
// Imported from registry to avoid duplication (N-2).
var ErrSSRFTargetForbidden = registry.ErrSSRFTargetForbidden

// SSRFGate validates upstream hosts against the provider allowlist and deny ranges.
type SSRFGate struct {
	allowedBaseURLs map[string][]string // from registry.AllowedProviderBaseURLs
	denyRanges      []*net.IPNet        // from registry.SSRFDenyRanges
}

// NewSSRFGate creates an SSRFGate using the compiled-in allowlist and deny ranges.
func NewSSRFGate() *SSRFGate {
	return &SSRFGate{
		allowedBaseURLs: registry.AllowedProviderBaseURLs,
		denyRanges:      registry.SSRFDenyRanges,
	}
}

// Validate checks the upstream host at request time:
//  1. Verifies provider is in the allowlist (fail-closed — unknown providers are denied).
//  2. Verifies host is in the provider's allowlist (if non-empty).
//  3. Resolves DNS.
//  4. Verifies resolved IPs are not in denyRanges.
func (g *SSRFGate) Validate(providerID, host string) error {
	// Step 1: fail-closed for unknown providers.
	allowed, ok := g.allowedBaseURLs[providerID]
	if !ok {
		return fmt.Errorf("%w: provider %q has no allowlist entry", ErrSSRFTargetForbidden, providerID)
	}

	// Step 2: allowlist check (len==0 means operator-configured, any host allowed but DNS check still applies).
	if len(allowed) > 0 {
		if !hostInAllowlist(host, allowed) {
			return fmt.Errorf("ssrf_gate: host %q not in allowlist for provider %q: %w",
				host, providerID, ErrSSRFTargetForbidden)
		}
	}

	// Steps 3 & 4: DNS resolve and IP deny-list check.
	if err := g.verifyHost(host); err != nil {
		return err
	}
	return nil
}

// verifyHost resolves host and checks each IP against denyRanges.
func (g *SSRFGate) verifyHost(host string) error {
	// IP literal: check directly.
	if ip := net.ParseIP(host); ip != nil {
		return g.checkIP(ip)
	}
	// DNS resolve.
	addrs, err := net.LookupHost(host) //nolint:gosec // G704: host is the value being validated; this IS the SSRF gate performing DNS resolution to check resolved IPs against deny-ranges
	if err != nil {
		return fmt.Errorf("ssrf_gate: DNS lookup %q: %w", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if err := g.checkIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// checkIP returns ErrSSRFTargetForbidden if ip falls in any deny range.
func (g *SSRFGate) checkIP(ip net.IP) error {
	for _, network := range g.denyRanges {
		if network.Contains(ip) {
			return fmt.Errorf("ssrf_gate: IP %s is in deny range %s: %w", ip, network, ErrSSRFTargetForbidden)
		}
	}
	return nil
}

// hostInAllowlist returns true if host is in the list.
func hostInAllowlist(host string, list []string) bool {
	for _, h := range list {
		if h == host {
			return true
		}
	}
	return false
}
