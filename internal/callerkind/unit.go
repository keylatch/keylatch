package callerkind

import (
	"errors"
	"strings"
	"testing"
)

// serviceUnit returns the enrolled-looking systemd service unit this process
// runs in: a non-transient .service in its cgroup. It reads the cgroup and asks
// systemd, never the environment, so a caller cannot claim to be a service by
// setting a variable. Replaced in tests; test binaries see no unit unless a
// test installs one.
var serviceUnit = func() (string, bool) {
	if testing.Testing() {
		return "", false
	}
	return detectServiceUnit()
}

// SetServiceUnit makes Local see the process as running in unit (or in none
// when unit is empty) and returns a function that restores the detection. It
// panics outside tests.
func SetServiceUnit(unit string) (restore func()) {
	if !testing.Testing() {
		panic("callerkind: SetServiceUnit is only available in tests")
	}
	prev := serviceUnit
	serviceUnit = func() (string, bool) { return unit, unit != "" }
	return func() { serviceUnit = prev }
}

// unitInfo is what systemd reports about a unit.
type unitInfo struct {
	Transient    bool
	FragmentPath string
}

// unitFromCgroup finds the service unit named by a /proc/<pid>/cgroup dump.
// The innermost .service element wins; the user manager itself (user@N.service)
// is not a unit a program runs in. user reports a unit of the user manager.
func unitFromCgroup(dump string) (unit string, user bool, ok bool) {
	for _, line := range strings.Split(dump, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || (parts[1] != "" && parts[1] != "name=systemd") {
			continue
		}
		elems := strings.Split(parts[2], "/")
		for i := len(elems) - 1; i >= 0; i-- {
			e := elems[i]
			if !strings.HasSuffix(e, ".service") || strings.HasPrefix(e, "user@") {
				continue
			}
			for _, outer := range elems[:i] {
				if strings.HasPrefix(outer, "user@") {
					user = true
				}
			}
			return e, user, true
		}
	}
	return "", false, false
}

// parseUnitInfo reads the output of `systemctl show -p Transient,FragmentPath`.
func parseUnitInfo(out string) (unitInfo, error) {
	var info unitInfo
	seen := false
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "Transient":
			info.Transient = v == "yes"
			seen = true
		case "FragmentPath":
			info.FragmentPath = v
		}
	}
	if !seen {
		return unitInfo{}, errors.New("systemctl reported no Transient property")
	}
	return info, nil
}

// serviceFromCgroup applies the rule: a unit counts only when systemd says it
// is not transient and has a unit file on disk. A scope or service created by
// systemd-run, or an agent's own transient unit, is not a service.
func serviceFromCgroup(dump string, show func(unit string, user bool) (unitInfo, error)) (string, bool) {
	unit, user, ok := unitFromCgroup(dump)
	if !ok {
		return "", false
	}
	info, err := show(unit, user)
	if err != nil || info.Transient || info.FragmentPath == "" {
		return "", false
	}
	return unit, true
}
