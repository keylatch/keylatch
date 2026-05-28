package exec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// CommandRunner is the interface for invoking external binaries. All calls to
// /usr/bin/security, op, bw, sops, etc. must go through this interface.
// S1-8: implementations must reject relative paths.
type CommandRunner interface {
	// Run executes name with args. stdin is piped to the process if non-nil.
	// Returns stdout, stderr, exit code, and any execution error.
	// The implementation MUST NOT invoke "sh -c" or interpolate user input into args.
	Run(ctx context.Context, name string, args []string, stdin []byte) (stdout, stderr []byte, exitCode int, err error)
}

// DefaultRunner is the process-level CommandRunner using os/exec.CommandContext.
// It never invokes "sh -c" and never interpolates user input into the command
// name or arg list.
var DefaultRunner CommandRunner = defaultRunner{}

// defaultRunner is the real CommandRunner implementation.
type defaultRunner struct{}

// Run implements CommandRunner using os/exec.CommandContext.
// S1-8: rejects relative paths before any exec call.
func (defaultRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	// S1-8: reject relative paths — only absolute paths are accepted.
	if !strings.HasPrefix(name, "/") {
		return nil, nil, 0, fmt.Errorf("exec: relative path rejected: %s", name)
	}

	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: name is validated to be an absolute path by the HasPrefix check above

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	stdout := stdoutBuf.Bytes()
	stderr := stderrBuf.Bytes()

	if err != nil {
		var exitErr *exec.ExitError
		if ok := isExitError(err, &exitErr); ok {
			return stdout, stderr, exitErr.ExitCode(), nil
		}
		return stdout, stderr, 0, err
	}

	return stdout, stderr, 0, nil
}

// isExitError checks if err is an *exec.ExitError and sets target if so.
func isExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}
