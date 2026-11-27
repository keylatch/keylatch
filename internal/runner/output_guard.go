package runner

import (
	"fmt"
	"io"

	"github.com/keylatch/keylatch/internal/redactor"
)

// outputGuard redacts exact secret values (and their encodings) from a
// child's relayed output and scans the files the child wrote afterwards.
type outputGuard struct {
	matcher *redactor.Matcher
	snap    *redactor.Snapshot
	policy  redactor.ScanPolicy
	diag    io.Writer
	out     *redactor.Writer
	err     *redactor.Writer
}

// newOutputGuard wraps stdout and stderr for a child that runs in dir ("" is
// the current directory). The matcher copies what it needs from secrets, so
// callers may zero them afterwards.
func newOutputGuard(stdout, stderr io.Writer, dir string, policy redactor.ScanPolicy, secrets ...[]byte) *outputGuard {
	g := &outputGuard{matcher: redactor.NewMatcher(secrets...), policy: policy, diag: stderr}
	g.out = g.matcher.NewWriter(stdout)
	if sameWriter(stdout, stderr) {
		g.err = g.out
	} else {
		g.err = g.matcher.NewWriter(stderr)
	}
	if dir == "" {
		dir = "."
	}
	snap, err := redactor.TakeSnapshot(dir)
	if err != nil {
		fmt.Fprintf(g.diag, "keylatch: written-file scan skipped: %v\n", err)
		return g
	}
	g.snap = snap
	return g
}

func (g *outputGuard) Stdout() io.Writer { return g.out }
func (g *outputGuard) Stderr() io.Writer { return g.err }

// Finish releases held-back output, scans files written by the child and
// returns how many contained a secret value or encoding.
func (g *outputGuard) Finish() int {
	_ = g.out.Close()
	_ = g.err.Close()
	if g.snap == nil {
		return 0
	}
	findings, err := g.matcher.ScanChanged(g.snap, g.policy)
	if err != nil {
		fmt.Fprintf(g.diag, "keylatch: written-file scan failed: %v\n", err)
	}
	for _, f := range findings {
		switch {
		case f.Unscanned:
			fmt.Fprintf(g.diag, "keylatch: changed file too large to scan: %s\n", f.Path)
		case f.Redacted:
			fmt.Fprintf(g.diag, "keylatch: secret value redacted in file written by the command: %s\n", f.Path)
		default:
			fmt.Fprintf(g.diag, "keylatch: secret value found in file written by the command: %s\n", f.Path)
		}
	}
	return len(findings)
}

func sameWriter(a, b io.Writer) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}
