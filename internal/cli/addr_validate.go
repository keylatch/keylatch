package cli

import (
	"fmt"
	"net"
	"strconv"
)

// addr_validate.go — input validation (docker-server-security hardening pass).
//
// KEYLATCH_GATEWAY_ADDR, KEYLATCH_PROXY_ADDR, and KEYLATCH_UI_ADDR are
// operator-controlled env vars that end up feeding net.Listen (gateway/proxy
// server startup) or net.Dial (client calls to a running keylatchd/gateway).
// A malformed value previously surfaced as an opaque low-level network error
// deep inside net/http; validateHostPort gives a single, clear, actionable
// error message up front instead.

// validateHostPort reports an error if addr is not syntactically valid
// host:port, or if the port is not a number in [1, 65535].
//
// An empty host (":7878") is accepted — net.Listen treats that as "all
// interfaces", which is a valid (if broad) bind address; the LLM-session
// fail-closed checks in internal/ui and internal/gateway are the actual
// gate on non-loopback binds, not this validator.
func validateHostPort(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: expected host:port — %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid address %q: port must be an integer between 1 and 65535", addr)
	}
	_ = host
	return nil
}
