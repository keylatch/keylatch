// Package egress is the only way out of a contained child's network namespace.
// The child's forwarder hands each connection to a Proxy, which allows a
// destination only when the run's policy names it and only after the proxy
// itself resolved the name to addresses that are not private, link-local or
// cloud-metadata ranges. The child never resolves a name, so a rebinding DNS
// answer cannot move a connection from an allowed name to an internal address.
package egress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
)

const (
	dialTimeout = 15 * time.Second
)

// Policy is what a run's children may reach.
type Policy struct {
	// Allow lists destinations as host[:port] patterns; the port defaults to
	// 443 and a leading "*." matches the labels below a suffix.
	Allow []string
	// AllowPrivate lists exact private or loopback addresses (or CIDRs) the
	// policy names, which are otherwise blocked.
	AllowPrivate []string
}

// Resolver resolves a host name to addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Proxy serves HTTP proxy requests on connections it is handed.
type Proxy struct {
	Policy   Policy
	Resolver Resolver
	// Dial opens the upstream connection to an address the proxy already
	// vetted. Nil dials with net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// OnDeny is told about every refused destination.
	OnDeny func(host, reason string)
	// Canary reports whether bytes hold a decoy credential. A request that
	// does is refused before it is forwarded and reported to OnCanary; a
	// tunnel's content is opaque, so only its target is checked.
	Canary   func([]byte) bool
	OnCanary func(host, where string)

	privateNets []netip.Prefix
	once        sync.Once
}

func (p *Proxy) init() {
	p.once.Do(func() {
		if p.Resolver == nil {
			p.Resolver = net.DefaultResolver
		}
		if p.Dial == nil {
			p.Dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
		}
		for _, s := range p.Policy.AllowPrivate {
			if pf, err := netip.ParsePrefix(s); err == nil {
				p.privateNets = append(p.privateNets, pf)
			} else if a, err := netip.ParseAddr(s); err == nil {
				p.privateNets = append(p.privateNets, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	})
}

// blockedRanges are never reachable unless the policy names them: private,
// shared, link-local (including 169.254.169.254) and unique-local networks.
var blockedRanges = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// Blocked reports whether addr is in a range a contained child may not reach
// unless the policy names it.
func Blocked(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, pf := range blockedRanges {
		if pf.Contains(addr) {
			return true
		}
	}
	return false
}

// Allowed reports whether the policy lets a child connect to host:port.
func (p *Proxy) Allowed(host, port string) bool {
	authority := net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port)
	for _, pat := range p.Policy.Allow {
		if registry.MatchAuthority(pat, authority) {
			return true
		}
	}
	return false
}

func (p *Proxy) deny(host, reason string) {
	if p.OnDeny != nil {
		p.OnDeny(host, reason)
	}
}

var errDenied = errors.New("destination not allowed")

// connect resolves host, refuses blocked addresses and dials the first
// permitted one. Dialing by address leaves nothing to rebind.
func (p *Proxy) connect(ctx context.Context, host, port string) (net.Conn, error) {
	p.init()
	if _, err := netip.ParseAddr(host); err == nil {
		// A literal address is reachable only when the policy names it exactly.
		if !p.Allowed(host, port) {
			p.deny(host, "ip_literal")
			return nil, errDenied
		}
	} else if !p.Allowed(host, port) {
		p.deny(host, "not_allowed")
		return nil, errDenied
	}
	addrs, err := p.addresses(ctx, host)
	if err != nil {
		return nil, err
	}
	var permitted []netip.Addr
	for _, a := range addrs {
		if p.privateAllowed(a) || !Blocked(a) {
			permitted = append(permitted, a.Unmap())
		}
	}
	if len(permitted) == 0 {
		p.deny(host, "blocked_range")
		return nil, errDenied
	}
	var lastErr error
	for _, a := range permitted {
		c, err := p.Dial(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (p *Proxy) privateAllowed(a netip.Addr) bool {
	for _, pf := range p.privateNets {
		if pf.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

func (p *Proxy) addresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return p.Resolver.LookupNetIP(ctx, "ip", host)
}

// ServeConn speaks the HTTP proxy protocol on conn until it closes: CONNECT
// tunnels to allowed hosts and absolute-URI requests for plain HTTP.
func (p *Proxy) ServeConn(conn net.Conn) {
	p.init()
	defer func() { _ = conn.Close() }()
	r := bufio.NewReaderSize(conn, 8<<10)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, err := http.ReadRequest(r)
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if where := p.canaryIn(req); where != "" {
		host, _, _ := splitHostPort(req.Host, "443")
		if p.OnCanary != nil {
			p.OnCanary(host, where)
		}
		reply(conn, http.StatusForbidden, "keylatch: a canary credential was sent; the run is ended")
		return
	}
	if req.Method == http.MethodConnect {
		p.tunnel(conn, r, req)
		return
	}
	p.plain(conn, req)
}

// maxCanaryBody bounds the request body read to look for a decoy.
const maxCanaryBody = 1 << 20

// canaryIn reports where a decoy appears in the request: its target, its head
// or, for plain HTTP, the start of its body.
func (p *Proxy) canaryIn(req *http.Request) string {
	if p.Canary == nil {
		return ""
	}
	hit := func(s string) bool { return p.Canary([]byte(s)) || p.Canary([]byte(unescape(s))) }
	switch {
	case hit(req.Host):
		return "connect_target"
	case req.URL != nil && hit(req.URL.String()):
		return "url"
	}
	for name, values := range req.Header {
		if hit(name) {
			return "header_name"
		}
		for _, v := range values {
			if hit(v) {
				return "header:" + strings.ToLower(name)
			}
		}
	}
	if req.Body != nil && req.Body != http.NoBody && req.ContentLength > 0 && req.ContentLength <= maxCanaryBody {
		data, err := io.ReadAll(io.LimitReader(req.Body, maxCanaryBody+1))
		if err == nil && p.Canary(data) {
			return "body"
		}
		req.Body = io.NopCloser(bytes.NewReader(data))
	}
	return ""
}

func unescape(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

func splitHostPort(authority, defaultPort string) (host, port string, ok bool) {
	h, pt, err := net.SplitHostPort(authority)
	if err != nil {
		if strings.Contains(authority, ":") && !strings.HasPrefix(authority, "[") {
			return "", "", false
		}
		h, pt = strings.Trim(authority, "[]"), defaultPort
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	return h, pt, h != "" && pt != ""
}

func reply(conn net.Conn, status int, msg string) {
	body := fmt.Sprintf(`{"error":"egress_denied","message":%q}`, msg)
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

func (p *Proxy) tunnel(conn net.Conn, r *bufio.Reader, req *http.Request) {
	host, port, ok := splitHostPort(req.Host, "443")
	if !ok {
		reply(conn, http.StatusBadRequest, "invalid CONNECT target")
		return
	}
	up, err := p.connect(context.Background(), host, port)
	if err != nil {
		if errors.Is(err, errDenied) {
			reply(conn, http.StatusForbidden, "keylatch: "+host+" is not reachable from this run")
		} else {
			reply(conn, http.StatusBadGateway, "keylatch: could not reach "+host)
		}
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		// Bytes the client sent behind the CONNECT head are already buffered.
		_, _ = io.Copy(up, io.MultiReader(io.LimitReader(r, int64(r.Buffered())), conn))
		if tc, ok := up.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, up)
		_ = conn.SetReadDeadline(time.Now())
		done <- struct{}{}
	}()
	<-done
	<-done
}

// plain forwards one plain-HTTP request to an allowed host and closes the
// connection.
func (p *Proxy) plain(conn net.Conn, req *http.Request) {
	if req.URL == nil || req.URL.Scheme != "http" || req.URL.Host == "" {
		reply(conn, http.StatusBadRequest, "this proxy accepts CONNECT and absolute http:// requests only")
		return
	}
	host, port, ok := splitHostPort(req.URL.Host, "80")
	if !ok {
		reply(conn, http.StatusBadRequest, "invalid request target")
		return
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return p.connect(ctx, host, port) },
		Proxy:       nil,
	}
	defer tr.CloseIdleConnections()
	out := req.Clone(req.Context())
	out.RequestURI = ""
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection"} {
		out.Header.Del(h)
	}
	resp, err := tr.RoundTrip(out)
	if err != nil {
		if errors.Is(err, errDenied) {
			reply(conn, http.StatusForbidden, "keylatch: "+host+" is not reachable from this run")
		} else {
			reply(conn, http.StatusBadGateway, "keylatch: could not reach "+host)
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()
	resp.Close = true
	_ = resp.Write(conn)
}
