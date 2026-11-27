//go:build linux

package presence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// polkitAction is declared in packaging/linux/polkit/dev.keylatch.policy.
const polkitAction = "dev.keylatch.privileged"

// Fixed locations: PATH is the caller's, and a planted pkcheck on it would
// approve everything.
var (
	pkcheckPaths   = []string{"/usr/bin/pkcheck", "/bin/pkcheck"}
	polkitPolicies = []string{"/usr/share/polkit-1/actions/dev.keylatch.policy", "/etc/polkit-1/actions/dev.keylatch.policy"}
)

type polkit struct {
	pkcheck string
	pid     int
	start   func(pid int) (string, error)
}

// platformMethod returns the polkit method when pkcheck and the keylatch
// action are both installed, and nil otherwise so hosts without polkit are
// not locked out.
func platformMethod() Method {
	bin := firstExisting(pkcheckPaths)
	if bin == "" || firstExisting(polkitPolicies) == "" {
		return nil
	}
	return &polkit{pkcheck: bin, pid: os.Getpid(), start: procStartTime}
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func (*polkit) Name() string { return "polkit" }

// Confirm asks polkit to authenticate the user for this process. The start
// time pins the check to this process even if its PID is reused.
func (p *polkit) Confirm(ctx context.Context, action Action, summary string) error {
	start, err := p.start(p.pid)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	cmd := exec.CommandContext(ctx, p.pkcheck, "--action-id", polkitAction, "--process", fmt.Sprintf("%d,%s,%d", p.pid, start, os.Getuid()), "--allow-user-interaction", "--detail", "polkit.message", string(action)+"\n"+summary) //nolint:gosec // fixed binary path, separate arguments
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("polkit refused (exit %d)", exit.ExitCode())
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// procStartTime returns field 22 of /proc/<pid>/stat, the process start time in
// clock ticks since boot.
func procStartTime(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	return parseStartTime(string(b))
}

func parseStartTime(stat string) (string, error) {
	// comm may contain spaces and parentheses; the fields start after the last ')'.
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return "", errors.New("malformed /proc stat")
	}
	fields := strings.Fields(stat[i+1:])
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return "", errors.New("short /proc stat")
	}
	return fields[19], nil
}
