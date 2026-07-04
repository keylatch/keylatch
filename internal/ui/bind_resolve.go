package ui

import (
	"fmt"
	"strconv"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// EnvListenKey is the environment variable that permits the UI server to
// bind to a non-loopback address (e.g. for reachability from a Docker
// container's host network). It is a Docker-oriented alternative to
// --unsafe-bind-all: functionally equivalent (both ultimately require
// ServerOptions.AllowExternalBind=true and both are still subject to New's
// LLM-session fail-closed check), but --listen/EnvListenKey let the operator
// specify the exact advertised address instead of always binding 0.0.0.0.
const EnvListenKey = "KEYLATCH_UI_LISTEN"

// ResolveBindAddr computes the UI server's bind address and whether a
// non-loopback bind should be explicitly permitted (ServerOptions.AllowExternalBind).
//
// Precedence (highest first):
//  1. listenFlag (--listen)
//  2. KEYLATCH_UI_LISTEN env var
//  3. existing behaviour: --unsafe-bind-all -> "0.0.0.0:<port>", else "127.0.0.1:<port>"
//
// Callers MUST still pass the result through New(), which enforces the
// fail-closed rule: any non-loopback bind is rejected outright when
// llmcontext.IsLLMSession is true, regardless of what this function returns.
func ResolveBindAddr(port int, listenFlag string, unsafeBindAll bool, env llmcontext.Lookup) (bind string, allowExternal bool) {
	bind = fmt.Sprintf("127.0.0.1:%d", port)
	if unsafeBindAll {
		bind = "0.0.0.0:" + strconv.Itoa(port)
		allowExternal = true
	}

	if listenFlag != "" {
		return listenFlag, true
	}
	if env != nil {
		if v := env(EnvListenKey); v != "" {
			return v, true
		}
	}
	return bind, allowExternal
}
