package exec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
)

// RunExact runs the absolute path name with exactly env as its environment.
// Unlike CommandRunner.RunEnv it inherits nothing from this process, so a
// backend that hands a CLI its own credential can be sure the CLI sees no
// other. A non-zero exit is reported through exitCode, not err.
func RunExact(ctx context.Context, name string, args, env []string) (stdout, stderr []byte, exitCode int, err error) {
	if !filepath.IsAbs(name) {
		return nil, nil, 0, fmt.Errorf("exec: relative path rejected: %s", name)
	}
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: name is an absolute path chosen by the backend, the arguments are built by it
	// An empty slice, not nil: nil would inherit the environment.
	cmd.Env = append([]string{}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if runErr := cmd.Run(); runErr != nil {
		var ee *exec.ExitError
		if isExitError(runErr, &ee) {
			return out.Bytes(), errOut.Bytes(), ee.ExitCode(), nil
		}
		return out.Bytes(), errOut.Bytes(), 0, runErr
	}
	return out.Bytes(), errOut.Bytes(), 0, nil
}
