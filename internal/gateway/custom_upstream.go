package gateway

import (
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/gateway/route"
)

var errCustomUpstream = errors.New("custom upstream URL rejected")

// customUpstreamURL builds the credentialed URL of a custom-secret request. The
// scheme and host come from the approved rule's host list, never from the
// request; the request contributes only an escaped path after the host and its
// query after "?". The result is re-parsed and must still name that host.
func customUpstreamURL(rt *route.Route, rawQuery string) (string, error) {
	var host string
	if i := slices.Index(rt.Custom.Hosts, rt.UpstreamHost); i >= 0 {
		host = rt.Custom.Hosts[i]
	}
	if host == "" || !safeUpstreamPath(rt.UpstreamPath) {
		return "", errCustomUpstream
	}
	target := "https://" + host + (&url.URL{Path: rt.UpstreamPath}).EscapedPath()
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host != host || u.User != nil || u.Port() != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errCustomUpstream
	}
	return target, nil
}

// safeUpstreamPath accepts only an absolute, canonical path with no authority
// or control characters.
func safeUpstreamPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "\\") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
