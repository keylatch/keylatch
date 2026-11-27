//go:build linux

package callerkind

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// systemctlPaths are fixed: PATH belongs to the caller.
var systemctlPaths = []string{"/usr/bin/systemctl", "/bin/systemctl"}

func detectServiceUnit() (string, bool) {
	dump, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	return serviceFromCgroup(string(dump), systemctlShow)
}

func systemctlShow(unit string, user bool) (unitInfo, error) {
	bin := ""
	for _, p := range systemctlPaths {
		if _, err := os.Stat(p); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return unitInfo{}, fmt.Errorf("systemctl not found")
	}
	args := []string{"show", "-p", "Transient,FragmentPath", unit}
	if user {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).Output() //nolint:gosec // fixed binary, unit name comes from our own cgroup
	if err != nil {
		return unitInfo{}, err
	}
	return parseUnitInfo(string(out))
}
