package ui

import (
	"net"
	"strings"
)

// isLoopbackBind returns true if the bind address is a loopback address.
// Handles IPv4 (127.x.x.x), IPv6 ([::1]), and "localhost".
// Uses net.SplitHostPort and net.ParseIP for correctness — not a string prefix check.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// addr may not have a port — treat the whole string as the host,
		// stripping brackets for bare IPv6 literals like "[::1]".
		host = strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
		if host == "" {
			host = addr
		}
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
