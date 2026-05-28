package exec

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// RealProbe implements Probe using exec.LookPath and exec.CommandContext.
type RealProbe struct{}

// Find looks up bin using exec.LookPath.
func (RealProbe) Find(_ context.Context, bin string) (string, bool, error) {
	p, err := exec.LookPath(bin)
	if err != nil {
		if isNotFound(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return p, true, nil
}

// Version runs path --version and returns the first line of stdout.
func (RealProbe) Version(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, path, "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run() // ignore exit code — many tools exit non-zero for --version
	line := strings.SplitN(strings.TrimSpace(out.String()), "\n", 2)[0]
	return line, nil
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "not found") ||
		strings.Contains(s, "no such file") ||
		strings.Contains(s, "executable file not found")
}
