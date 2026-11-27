package contained

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// restrictor applies the one-way restrictions of a contained child to the
// calling OS thread. The real implementation changes the process; tests
// replace it.
type restrictor interface {
	NoNewPrivs() error
	DropCapabilities() error
	LandlockABI() int
	Landlock(plan landlockPlan) error
	Seccomp(prog []unix.SockFilter) error
}

type hostRestrictor struct{}

func (hostRestrictor) NoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func (hostRestrictor) LandlockABI() int                     { return landlockABI() }
func (hostRestrictor) Landlock(plan landlockPlan) error     { return plan.apply() }
func (hostRestrictor) Seccomp(prog []unix.SockFilter) error { return installFilter(prog) }
func (hostRestrictor) DropCapabilities() error {
	return dropCapabilities("/proc/sys/kernel/cap_last_cap")
}

// dropCapabilities empties the bounding, inheritable, permitted, effective and
// ambient sets so that nothing the child executes can regain a capability.
func dropCapabilities(lastCapFile string) error {
	last := 40
	if b, err := os.ReadFile(lastCapFile); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			last = n
		}
	}
	var dropErr error
	for c := 0; c <= last; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			dropErr = err
		}
	}
	_ = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("contained: drop capabilities: %w", err)
	}
	if dropErr != nil {
		return fmt.Errorf("contained: drop bounding capabilities: %w", dropErr)
	}
	return nil
}

// restrict applies, in order, no_new_privs, the empty capability sets,
// Landlock and the seccomp filter. Landlock comes before seccomp because the
// filter forbids nothing Landlock needs, and both must precede the exec.
func restrict(r restrictor, spec Spec) error {
	if err := r.NoNewPrivs(); err != nil {
		return fmt.Errorf("contained: no_new_privs: %w", err)
	}
	if err := r.DropCapabilities(); err != nil {
		return err
	}
	abi := r.LandlockABI()
	if abi < 1 {
		return errors.New("contained: the kernel has no Landlock; refusing to run without it")
	}
	ro, rw := sandboxPaths(spec)
	ports := append([]int{spec.ProxyPort}, spec.ConnectPorts...)
	if err := r.Landlock(newLandlockPlan(abi, ro, rw, ports)); err != nil {
		return err
	}
	return r.Seccomp(defaultFilter(spec.AllowIOUring))
}
