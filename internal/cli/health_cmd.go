package cli

import (
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/daemon"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// health_cmd.go — value-free readiness check for container HEALTHCHECK use.
//
// A distroless image has no shell, so a Dockerfile HEALTHCHECK must invoke
// the keylatch binary itself rather than a shell one-liner:
//
//	HEALTHCHECK CMD ["/keylatch", "health"]
//
// The command name MUST be exactly "health" — a parallel packaging lane's
// Dockerfile already references ["/keylatch","health"].
//
// docker HEALTHCHECK exit code contract: 0 = healthy, 1 = unhealthy, 2 =
// reserved by Docker. This command therefore uses the literal exit codes 0/1
// rather than internal/exitcode's constants (which encode unrelated CLI
// semantics, e.g. exitcode.SecurityBlock == 2, which would collide with
// Docker's reserved code).
//
// Never reads or prints credential values — only stats config/keyring paths
// for readability and (optionally) probes a running server's /health
// endpoint. Absence of config/keyring is healthy (a freshly-created
// container has not been bootstrapped yet); unreadable-but-present is not.

// healthCheckResult is the pure, testable result of a health check — no I/O
// side effects (no os.Exit), so it can be exercised directly by unit tests
// without terminating the test process.
type healthCheckResult struct {
	Healthy bool
	Lines   []string
}

// checkHealth runs the readiness checks and returns a pure result. daemonUp
// is injected for testability; production callers pass daemon.IsRunning.
func checkHealth(env llmcontext.Lookup, probeServer bool, daemonUp func() bool) healthCheckResult {
	res := healthCheckResult{Healthy: true}

	// Config directory: must be readable if present. Absence is healthy —
	// not yet bootstrapped is a normal state for a fresh container.
	cfgPath := paths.Config(env)
	if _, err := os.Stat(cfgPath); err != nil {
		if os.IsNotExist(err) {
			res.Lines = append(res.Lines, "config: not present (not bootstrapped)")
		} else {
			res.Healthy = false
			res.Lines = append(res.Lines, "config: NOT READABLE")
		}
	} else {
		res.Lines = append(res.Lines, "config: ok")
	}

	// Keyring file: must be readable if present. Absence is healthy.
	krPath := paths.KeyringPath(env)
	if _, err := os.Stat(krPath); err != nil {
		if os.IsNotExist(err) {
			res.Lines = append(res.Lines, "keyring: not present (not bootstrapped)")
		} else {
			res.Healthy = false
			res.Lines = append(res.Lines, "keyring: NOT READABLE")
		}
	} else {
		res.Lines = append(res.Lines, "keyring: ok")
	}

	if probeServer {
		// Best-effort only — an unreachable server never fails the healthcheck
		// by itself (a container may run the CLI without a long-running
		// server component at all).
		if daemonUp != nil && daemonUp() {
			res.Lines = append(res.Lines, "server: reachable")
		} else {
			res.Lines = append(res.Lines, "server: not reachable (informational)")
		}
	}

	if res.Healthy {
		res.Lines = append(res.Lines, "healthy")
	} else {
		res.Lines = append(res.Lines, "unhealthy")
	}
	return res
}

func newHealthCmd() *cobra.Command {
	var probeServer bool

	cmd := &cobra.Command{
		Use:    "health",
		Short:  "Check local readiness (safe for container HEALTHCHECK)",
		Hidden: true, // operational plumbing, not a daily-use command
		Long: `Prints a short readiness summary and exits 0 if keylatch's local
state is readable, or 1 otherwise. Never reads or prints credential values.

Checks:
  - config directory: readable if present (absence is healthy — not yet
    bootstrapped is a normal state for a fresh container)
  - keyring file: readable if present (same absence rule)
  - --probe-server: best-effort check that a local keylatchd server responds;
    never fails the healthcheck on its own (an optional, informational check)

Safe to use as a distroless container HEALTHCHECK, which has no shell and
must invoke the binary directly:

  HEALTHCHECK CMD ["/keylatch", "health"]`,
		RunE: func(c *cobra.Command, _ []string) error {
			res := checkHealth(llmcontext.DefaultLookup, probeServer, daemon.IsRunning)
			out := c.OutOrStdout()
			for _, l := range res.Lines {
				fmt.Fprintln(out, l)
			}
			if !res.Healthy {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&probeServer, "probe-server", false,
		"also probe a local keylatchd server (best-effort; never fails the healthcheck on its own)")
	return cmd
}
