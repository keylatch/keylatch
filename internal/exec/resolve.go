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
func MustResolve(bin string) string {
	p := Resolve(bin)
	if p == "" {
		panic(fmt.Sprintf("exec: required binary %q not found in PATH", bin))
	}
	return p
}
