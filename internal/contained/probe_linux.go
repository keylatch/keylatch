package contained

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// probeEnv is what Probe asks the host. Tests replace it.
type probeEnv struct {
	// namespace reports whether a process can start in a user namespace
	// combined with the given clone flags.
	namespace func(flags uintptr) error
	landlock  func() int
	seccomp   func() error
	// cgroup returns the controllers a run's leaf could be bounded by.
	cgroup func() (controllers []string, err error)
	// sysctl returns the trimmed content of a procfs file, or "".
	sysctl func(path string) string
}

func hostProbeEnv() probeEnv {
	return probeEnv{
		namespace: tryNamespace,
		landlock:  landlockABI,
		seccomp: func() error {
			_, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
			return err
		},
		cgroup: probeCgroup,
		sysctl: func(path string) string {
			b, _ := os.ReadFile(path)
			return strings.TrimSpace(string(b))
		},
	}
}

// Probe reports what this host lets the sandbox do.
func Probe() Report { return hostProbeEnv().report() }

func (e probeEnv) report() Report {
	r := Report{Backend: "native"}
	add := func(name string, err error, okDetail string) {
		c := Capability{Name: name, OK: err == nil, Detail: okDetail}
		if err != nil {
			c.Detail = err.Error()
		}
		r.Capabilities = append(r.Capabilities, c)
	}
	userErr := e.namespace(0)
	add("user_namespace", userErr, "unprivileged user namespaces work")
	if userErr != nil {
		if e.sysctl("/proc/sys/user/max_user_namespaces") == "0" {
			r.Capabilities[0].Detail += " (user.max_user_namespaces is 0)"
		}
		if e.sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1" {
			r.Capabilities[0].Detail += " (kernel.apparmor_restrict_unprivileged_userns is 1)"
		}
	}
	for _, ns := range []struct {
		name  string
		flags uintptr
	}{
		{"mount_namespace", syscall.CLONE_NEWNS}, {"pid_namespace", syscall.CLONE_NEWPID},
		{"net_namespace", syscall.CLONE_NEWNET}, {"cgroup_namespace", syscall.CLONE_NEWCGROUP},
	} {
		if userErr != nil {
			add(ns.name, fmt.Errorf("needs user_namespace"), "")
			continue
		}
		add(ns.name, e.namespace(ns.flags), "available")
	}
	add("seccomp", e.seccomp(), "filter mode available")
	abi := e.landlock()
	var lerr error
	if abi < 1 {
		lerr = fmt.Errorf("the kernel has no Landlock (needs Linux 5.13 or newer)")
	}
	add("landlock", lerr, "ABI "+strconv.Itoa(abi))
	var nerr error
	if abi < 4 {
		nerr = fmt.Errorf("Landlock ABI %d has no TCP rules (needs ABI 4, Linux 6.7); the network namespace still confines egress", abi)
	}
	add("landlock_network", nerr, "TCP connect is limited to the forwarder port")
	controllers, cerr := e.cgroup()
	add("cgroup_leaf", cerr, "kill-all and limits via controllers: "+strings.Join(controllers, ","))
	r.Supported = len(r.Missing()) == 0
	return r
}

func tryNamespace(flags uintptr) error {
	truePath, err := exec.LookPath("true")
	if err != nil {
		return fmt.Errorf("no `true` binary to probe with: %w", err)
	}
	cmd := exec.Command(truePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | flags,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot create the namespace: %w", err)
	}
	return nil
}

// probeCgroup checks that a leaf can be created below the cgroup the process
// runs in, and reports the controllers that cgroup offers.
func probeCgroup() ([]string, error) {
	parent, err := ownCgroup("/proc/self/cgroup", cgroupRoot)
	if err != nil {
		return nil, err
	}
	cg, err := newCgroup(parent, Limits{})
	if err != nil {
		return nil, fmt.Errorf("%w; runs are not bounded and cannot be killed through a cgroup", err)
	}
	defer cg.Remove()
	b, _ := os.ReadFile(filepath.Join(cg.dir, "cgroup.controllers"))
	return strings.Fields(string(b)), nil
}
