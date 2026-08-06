// Package gateway — best-effort process-identity verification for stale PID
// recovery.
package gateway

import (
	"context"
	"strconv"
	"strings"

	kexec "github.com/keylatch/keylatch/internal/exec"
)

// processIdentityKeywords are substrings that indicate a `ps` command-line
// output belongs to a keylatch gateway/daemon process.
var processIdentityKeywords = []string{"keylatchd", "keylatch"}

// VerifyProcessIdentity best-effort checks whether pid's command line looks
// like a keylatch gateway/daemon process, by running
// `ps -p <pid> -o command=` through runner and matching the output against
// processIdentityKeywords.
//
// This is NOT a security boundary — it exists purely to disambiguate
// ordinary PID-reuse races for `gateway up --force` stale-PID recovery
// (L2): IsRunning only signal-0-probes the pid, so a recycled pid can
// false-positive as "gateway running" when it actually belongs to an
// unrelated process.
//
// Returns (matched, checked). checked is false when the probe could not be
// performed at all (nil runner/psBin, exec error, non-zero exit, empty
// output) — callers must treat checked=false as "unable to verify" and
// decide their own fallback policy rather than trusting matched (which is
// meaningless when checked is false).
func VerifyProcessIdentity(ctx context.Context, runner kexec.CommandRunner, psBin string, pid int) (matched bool, checked bool) {
	if runner == nil || psBin == "" || pid <= 0 {
		return false, false
	}

	stdout, _, exitCode, err := runner.Run(ctx, psBin, []string{"-p", strconv.Itoa(pid), "-o", "command="}, nil)
	if err != nil || exitCode != 0 {
		return false, false
	}

	out := strings.ToLower(strings.TrimSpace(string(stdout)))
	if out == "" {
		return false, false
	}

	for _, kw := range processIdentityKeywords {
		if strings.Contains(out, kw) {
			return true, true
		}
	}
	return false, true
}
