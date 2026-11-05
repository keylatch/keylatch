package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/keylatch/keylatch/internal/registry"
)

// ErrSSRFTargetForbidden is the sentinel for SSRF policy violations.
// Imported from registry to avoid duplication.
var ErrSSRFTargetForbidden = registry.ErrSSRFTargetForbidden

// errUnpinnedDial is returned when an upstream connection is attempted for a
// host the SSRF gate did not resolve for this request.
var errUnpinnedDial = errors.New("ssrf_gate: dial to a host that was not validated for this request")

// SSRFGate validates upstream hosts against the provider allowlist and deny ranges.
type SSRFGate struct {
	allowedBaseURLs map[string][]string // from registry.AllowedProviderBaseURLs
	denyRanges      []*net.IPNet        // from registry.SSRFDenyRanges
	lookup          func(host string) ([]string, error)
}

// NewSSRFGate creates an SSRFGate using the compiled-in allowlist and deny ranges.
func NewSSRFGate() *SSRFGate {
	return &SSRFGate{
		allowedBaseURLs: registry.AllowedProviderBaseURLs,
		denyRanges:      registry.SSRFDenyRanges,
		lookup:          net.LookupHost,
	}
}

// Validate checks the upstream host at request time:
//  1. Verifies provider is in the allowlist (fail-closed — unknown providers are denied).
//  2. Verifies host is in the provider's allowlist (if non-empty).
//  3. Resolves DNS.
//  4. Verifies resolved IPs are not in denyRanges.
func (g *SSRFGate) Validate(providerID, host string) error {
	_, err := g.Resolve(providerID, host)
	return err
}

// Resolve runs Validate and returns the addresses it checked. The upstream
// connection must be made to exactly these addresses (see withPinnedIPs), so
// a DNS answer that changes between the check and the dial is never used.
func (g *SSRFGate) Resolve(providerID, host string) ([]net.IP, error) {
	// Step 1: fail-closed for unknown providers.
	allowed, ok := g.allowedBaseURLs[providerID]
	if !ok {
		return nil, fmt.Errorf("%w: provider %q has no allowlist entry", ErrSSRFTargetForbidden, providerID)
	}

	// Step 2: allowlist check (len==0 means operator-configured, any host allowed but DNS check still applies).
	if len(allowed) > 0 {
		if !hostInAllowlist(host, allowed) {
			return nil, fmt.Errorf("ssrf_gate: host %q not in allowlist for provider %q: %w",
				host, providerID, ErrSSRFTargetForbidden)
		}
	}

	// Steps 3 & 4: DNS resolve and IP deny-list check.
	return g.verifyHost(host)
}

// verifyHost resolves host and checks each IP against denyRanges. Every
// returned address is allowed.
func (g *SSRFGate) verifyHost(host string) ([]net.IP, error) {
	// IP literal: check directly.
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, g.checkIP(ip)
	}
	addrs, err := g.lookup(host)
	if err != nil {
		return nil, fmt.Errorf("ssrf_gate: DNS lookup %q: %w", host, err)
	}
	var ips []net.IP
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if err := g.checkIP(ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("ssrf_gate: DNS lookup %q returned no address", host)
	}
	return ips, nil
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

type pinnedKey struct{}

type pinnedHost struct {
	host string
	ips  []net.IP
}

// withPinnedIPs records the addresses the SSRF gate checked for host.
func withPinnedIPs(ctx context.Context, host string, ips []net.IP) context.Context {
	return context.WithValue(ctx, pinnedKey{}, pinnedHost{host: host, ips: ips})
}

// pinnedDialContext dials only the addresses pinned in ctx for the requested
// host and never resolves the name again. A dial for any other host, or with
// nothing pinned, is refused.
func pinnedDialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		pin, ok := ctx.Value(pinnedKey{}).(pinnedHost)
		if !ok || pin.host != host || len(pin.ips) == 0 {
			return nil, errUnpinnedDial
		}
		var lastErr error
		for _, ip := range pin.ips {
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
