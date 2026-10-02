// Package gateway — best-effort process-identity verification for stale PID
// recovery.
package gateway

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	kexec "github.com/keylatch/keylatch/internal/exec"
)

// processIdentityExeNames are the exact (case-insensitive) executable
// basenames that identify a keylatch gateway/daemon process.
var processIdentityExeNames = []string{"keylatchd", "keylatch"}

// VerifyProcessIdentity best-effort checks whether pid's command line looks
// like a keylatch gateway/daemon process, by running
// `ps -p <pid> -o command=` through runner and checking whether the
// basename of the first whitespace-separated token (the executable — ps
// -o command= does not shell-quote arguments, so a plain field-split is
// enough) exactly matches processIdentityExeNames.
//
// Anchoring on the executable token (rather than a substring match against
// the full command line, the previous behavior) avoids false positives like
// `vim /repos/keylatch/main.go` or `grep keylatch app.log` — commands whose
// *arguments* happen to contain "keylatch" but whose executable is
// completely unrelated.
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

	line := strings.TrimSpace(string(stdout))
	if line == "" {
		return false, false
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false, false
	}
	exe := strings.ToLower(filepath.Base(fields[0]))

	for _, name := range processIdentityExeNames {
		if exe == name {
			return true, true
		}
	}
	return false, true
}
