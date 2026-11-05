package contained

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	landlockRuleNetPort = 2

	fsAccessRead    = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	fsAccessReadExe = fsAccessRead | unix.LANDLOCK_ACCESS_FS_EXECUTE
	// fsAccessFile is what a rule on a non-directory may carry.
	fsAccessFile = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

type pathRule struct {
	path   string
	access uint64
}

// landlockPlan is the ruleset applied to the child: filesystem rules that
// mirror the mounts and, where the kernel has them, a rule that lets TCP
// connect only to the forwarder's port.
type landlockPlan struct {
	abi        int
	fsHandled  uint64
	netHandled uint64
	paths      []pathRule
	ports      []uint16
}

// landlockABI returns the kernel's Landlock ABI version, or 0 when Landlock is
// unavailable.
func landlockABI() int {
	v, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		return 0
	}
	return int(v)
}

// fsMask is every filesystem right the ABI can handle.
func fsMask(abi int) uint64 {
	mask := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		mask |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		mask |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		mask |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return mask
}

// newLandlockPlan lists the rules for a child that may read the paths in ro,
// read and write the paths in rw, and connect to the given loopback ports.
// Paths that do not exist are left out.
func newLandlockPlan(abi int, ro, rw []string, ports []int) landlockPlan {
	p := landlockPlan{abi: abi, fsHandled: fsMask(abi)}
	for _, path := range ro {
		if _, err := os.Stat(path); err == nil {
			p.paths = append(p.paths, pathRule{path, fsAccessReadExe & p.fsHandled})
		}
	}
	for _, path := range rw {
		if _, err := os.Stat(path); err == nil {
			p.paths = append(p.paths, pathRule{path, p.fsHandled})
		}
	}
	if abi >= 4 {
		p.netHandled = unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
		for _, port := range ports {
			p.ports = append(p.ports, uint16(port)) //nolint:gosec // G115: Spec.Validate bounds ports to 1..65535
		}
	}
	return p
}

type netPortAttr struct {
	allowed uint64
	port    uint64
}

// apply restricts the calling thread, and everything it starts, to the plan.
// no_new_privs must already be set.
func (p landlockPlan) apply() error {
	attr := unix.LandlockRulesetAttr{Access_fs: p.fsHandled, Access_net: p.netHandled}
	size := unsafe.Sizeof(attr.Access_fs)
	if p.abi >= 4 {
		size += unsafe.Sizeof(attr.Access_net)
	}
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0) //nolint:gosec // G103: the kernel reads the attribute struct during the call
	if e != 0 {
		return fmt.Errorf("contained: create landlock ruleset: %w", e)
	}
	defer func() { _ = unix.Close(int(fd)) }()

	for _, r := range p.paths {
		if err := addPathRule(int(fd), r); err != nil {
			return err
		}
	}
	for _, port := range p.ports {
		na := netPortAttr{allowed: unix.LANDLOCK_ACCESS_NET_CONNECT_TCP, port: uint64(port)}
		if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, landlockRuleNetPort, uintptr(unsafe.Pointer(&na)), 0, 0, 0); e != 0 { //nolint:gosec // G103: the kernel reads the rule struct during the call
			return fmt.Errorf("contained: landlock rule for port %d: %w", port, e)
		}
	}
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); e != 0 {
		return fmt.Errorf("contained: restrict with landlock: %w", e)
	}
	return nil
}

func addPathRule(ruleset int, r pathRule) error {
	pfd, err := unix.Open(r.path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("contained: landlock rule for %s: %w", r.path, err)
	}
	defer func() { _ = unix.Close(pfd) }()
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return fmt.Errorf("contained: landlock rule for %s: %w", r.path, err)
	}
	access := r.access
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		access &= fsAccessFile
	}
	attr := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(pfd)}                                                                           //nolint:gosec // G115: a file descriptor fits in int32
	if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0); e != 0 { //nolint:gosec // G103: the kernel reads the rule struct during the call
		if errors.Is(e, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("contained: landlock rule for %s: %w", r.path, e)
	}
	return nil
}
