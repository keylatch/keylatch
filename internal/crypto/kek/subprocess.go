package kek

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// subprocessTimeout bounds how long the op/bw manager CLI may run for a
// single KEK operation. Prevents a hung/interactive CLI (e.g. waiting on a
// biometric prompt or a dead session) from blocking indefinitely.
// Var (not const) so tests can shrink it instead of waiting out the real value.
var subprocessTimeout = 15 * time.Second

// maxSubprocessOutput bounds captured stdout so a misbehaving CLI cannot
// exhaust memory. Manager item/field payloads are always small.
// Var (not const) so tests can shrink it to exercise the bound cheaply.
var maxSubprocessOutput = 1 << 20 // 1 MiB

// runManagerCLI runs name with args, bounded by subprocessTimeout and
// maxSubprocessOutput, and returns captured stdout. It inherits the ambient
// process environment (managers such as op/bw resolve session state from
// HOME/config env vars) but never invokes a shell and never interpolates
// caller-controlled bytes into name or args.
func runManagerCLI(name string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), subprocessTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: name is always a literal manager-CLI name ("op", "bw", "security"), not user input
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &stdout, max: maxSubprocessOutput}
	cmd.Stderr = &limitedWriter{buf: &stderr, max: maxSubprocessOutput}

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("%s: timed out after %s", name, subprocessTimeout)
	}
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

// limitedWriter caps total bytes written before returning an error, bounding
// subprocess output capture regardless of what the child process emits.
type limitedWriter struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.max {
		return 0, fmt.Errorf("kek: subprocess output exceeds %d byte limit", l.max)
	}
	return l.buf.Write(p)
}
