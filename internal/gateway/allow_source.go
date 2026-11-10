package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
)

// ParseAllowSources parses CIDR strings for ServerOptions.AllowSources.
// IPv4-mapped IPv6 prefixes are refused: a connection from a mapped address
// is matched as plain IPv4, so the mapped form could never be reached.
func ParseAllowSources(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("allow-source %q is not a CIDR (for example 10.0.0.0/24 or fd00::/64)", c)
		}
		if p.Addr().Zone() != "" {
			return nil, fmt.Errorf("allow-source %q: zones are not supported", c)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("allow-source %q: use the IPv4 form of an IPv4-mapped prefix", c)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// sourceAllowed reports whether the TCP peer in remoteAddr is inside one of
// the prefixes. Only the connection's own address is consulted; forwarding
// headers are caller-controlled and never read.
func sourceAllowed(prefixes []netip.Prefix, remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// allowSourceMiddleware refuses callers outside prefixes before any other
// processing, so a refused peer learns nothing about routes or tokens.
func (s *Server) allowSourceMiddleware(next http.Handler, prefixes []netip.Prefix) http.Handler {
	if len(prefixes) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sourceAllowed(prefixes, r.RemoteAddr) {
			writeError(w, http.StatusForbidden, "source_not_allowed", "caller address is not allowed")
			s.logAudit(r.Context(), audit.ActionGatewayCall, audit.OutcomeDenied, map[string]any{
				"error": "source_not_allowed",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
