package exec

import (
	"fmt"
	"os/exec"
)

// Resolve returns the absolute path for bin using exec.LookPath.
// Returns "" if the binary is not found (no panic, no error).
// Used for optional binaries: op, bw, sops, docker.
func Resolve(bin string) string {
	p, err := exec.LookPath(bin)
	if err != nil {
		return ""
	}
	return p
}

// MustResolve returns the absolute path for bin.
// Panics with a clear message if the binary is not found.
// Used for required binaries that must be present at startup.
//
// M9b call-site audit (2026-08): MustResolve panics the calling goroutine —
// safe only when that panic terminates process startup, not when it can
// fire mid-request inside a long-running process (gateway/daemon/sidecar).
// As of this audit there is exactly one production call site:
// resolve_darwin.go's `var securityBin = MustResolve("/usr/bin/security")`,
// a package-level var initializer that runs once during process init
// (before main()), before any gateway/daemon request handling can start —
// startup-time, so it stays. If a future call site executes from inside a
// gateway handler, daemon request loop, or sidecar process, convert it to
// Resolve + explicit error handling instead of adding another MustResolve
// caller here.
func MustResolve(bin string) string {
	p := Resolve(bin)
	if p == "" {
		panic(fmt.Sprintf("exec: required binary %q not found in PATH", bin))
	}
	return p
}
