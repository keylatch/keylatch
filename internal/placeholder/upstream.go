package placeholder

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
)

// Upstream controls how the proxy reaches provider hosts. The zero value dials
// directly, resolves names itself and trusts the system roots; the fields exist
// so tests can stand local servers in for provider hosts.
type Upstream struct {
	// Roots replaces the system roots when verifying provider certificates.
	Roots *x509.CertPool
	// Dial replaces the guarded dialer. It receives the proxy address when the
	// session chains to an upstream proxy.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Lookup replaces name resolution.
	Lookup func(ctx context.Context, host string) ([]net.IP, error)
}

var errForbiddenTarget = errors.New("placeholder: destination is not reachable from a session")

var forbiddenNames = []string{"localhost", "ip6-localhost", "ip6-loopback", "metadata.google.internal", "metadata"}

func forbiddenName(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, n := range forbiddenNames {
		if host == n || strings.HasSuffix(host, "."+n) {
			return true
		}
	}
	return strings.HasSuffix(host, ".localhost")
}

// deniedIP reports whether ip is in a range sessions never reach: loopback,
// private, link-local, metadata, carrier-grade NAT, multicast and unspecified.
func deniedIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range registry.SSRFDenyRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (u Upstream) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if u.Lookup != nil {
		return u.Lookup(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// resolve returns the addresses host may be dialed at, or an error when the
// name or any address it resolves to is forbidden. One lookup feeds the dial,
// so a name cannot answer differently between the check and the connection.
func (u Upstream) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if forbiddenName(host) {
		return nil, fmt.Errorf("%w: %s", errForbiddenTarget, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if deniedIP(ip) {
			return nil, fmt.Errorf("%w: %s", errForbiddenTarget, host)
		}
		return []net.IP{ip}, nil
	}
	ips, err := u.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("placeholder: %s did not resolve", host)
	}
	for _, ip := range ips {
		if deniedIP(ip) {
			return nil, fmt.Errorf("%w: %s resolves to a restricted address", errForbiddenTarget, host)
		}
	}
	return ips, nil
}

// DialContext connects the way a session's proxy does: through Dial when set,
// otherwise by resolving the name itself and refusing loopback, private,
// link-local and metadata addresses. Protocol adapters use it so they reach
// the same hosts and no others.
func (u Upstream) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if u.Dial != nil {
		return u.Dial(ctx, network, addr)
	}
	return u.guardedDial(ctx, network, addr)
}

func (u Upstream) guardedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := u.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	var lastErr error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// checkChained validates a destination whose resolution the upstream proxy
// performs: forbidden names and address literals are refused outright, and a
// name this host can resolve must not resolve into a restricted range. A name
// only the upstream proxy can resolve is left to it.
func (u Upstream) checkChained(ctx context.Context, host string) error {
	if forbiddenName(host) {
		return fmt.Errorf("%w: %s", errForbiddenTarget, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if deniedIP(ip) {
			return fmt.Errorf("%w: %s", errForbiddenTarget, host)
		}
		return nil
	}
	ips, err := u.lookup(ctx, host)
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if deniedIP(ip) {
			return fmt.Errorf("%w: %s resolves to a restricted address", errForbiddenTarget, host)
		}
	}
	return nil
}

// parseChain validates the proxy URL a caller reports from its own
// environment. It returns nil when the caller reports none.
func parseChain(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("placeholder: upstream proxy %q is not a valid URL", raw)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("placeholder: upstream proxy scheme %q is not supported", u.Scheme)
	}
	return u, nil
}

func (u Upstream) transport(chain *url.URL) *http.Transport {
	t := &http.Transport{
		TLSClientConfig:       &tls.Config{RootCAs: u.Roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}
	switch {
	case chain != nil:
		t.Proxy = func(*http.Request) (*url.URL, error) { return chain, nil }
		if u.Dial != nil {
			t.DialContext = u.Dial
		}
	case u.Dial != nil:
		t.DialContext = u.Dial
	default:
		t.DialContext = u.guardedDial
	}
	return t
}
