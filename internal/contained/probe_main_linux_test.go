package contained

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestSandboxProbe is the hostile child of the escape tests. It runs inside
// the sandbox, attempts every way out it can think of and prints one JSON
// object that maps an attempt to its outcome. Outside the sandbox it does
// nothing.
func TestSandboxProbe(t *testing.T) {
	if os.Getenv("KEYLATCH_SANDBOX_PROBE") != "1" {
		t.Skip("runs only as the sandboxed child of the escape tests")
	}
	out := map[string]string{}
	record := func(name string, err error) {
		if err == nil {
			out[name] = "ok"
		} else {
			out[name] = errnoName(err)
		}
	}

	out["environ"] = strings.Join(os.Environ(), "\n")
	b, err := os.ReadFile("/proc/self/environ")
	record("read /proc/self/environ", err)
	out["proc_environ"] = strings.ReplaceAll(string(b), "\x00", "\n")

	syscalls := map[string][]uintptr{
		"ptrace":            {unix.SYS_PTRACE, unix.PTRACE_ATTACH, 1},
		"process_vm_readv":  {unix.SYS_PROCESS_VM_READV, 1, 0, 0, 0, 0},
		"process_vm_writev": {unix.SYS_PROCESS_VM_WRITEV, 1, 0, 0, 0, 0},
		"keyctl":            {unix.SYS_KEYCTL, 0},
		"add_key":           {unix.SYS_ADD_KEY, 0, 0, 0, 0, 0},
		"bpf":               {unix.SYS_BPF, 0, 0, 0},
		"perf_event_open":   {unix.SYS_PERF_EVENT_OPEN, 0, 0, 0, 0, 0},
		"userfaultfd":       {unix.SYS_USERFAULTFD, 0},
		"io_uring_setup":    {unix.SYS_IO_URING_SETUP, 8, 0},
		"unshare newuser":   {unix.SYS_UNSHARE, unix.CLONE_NEWUSER},
		"unshare newns":     {unix.SYS_UNSHARE, unix.CLONE_NEWNS},
		"setns":             {unix.SYS_SETNS, 0, 0},
		"pivot_root":        {unix.SYS_PIVOT_ROOT, 0, 0},
		"kexec_load":        {unix.SYS_KEXEC_LOAD, 0, 0, 0, 0},
		"init_module":       {unix.SYS_INIT_MODULE, 0, 0, 0},
		"reboot":            {unix.SYS_REBOOT, 0, 0, 0, 0},
		"open_by_handle_at": {unix.SYS_OPEN_BY_HANDLE_AT, 0, 0, 0},
		"fsopen":            {unix.SYS_FSOPEN, 0, 0},
		"mount_setattr":     {unix.SYS_MOUNT_SETATTR, 0, 0, 0, 0, 0},
		"pidfd_getfd":       {unix.SYS_PIDFD_GETFD, 0, 0, 0},
		"clone3 newuser":    {unix.SYS_CLONE3, 0, 0},
		"swapon":            {unix.SYS_SWAPON, 0, 0},
		"chroot":            {unix.SYS_CHROOT, 0},
	}
	for name, args := range syscalls {
		a := append(args, 0, 0, 0, 0, 0, 0, 0)
		_, _, e := unix.Syscall6(args[0], a[1], a[2], a[3], a[4], a[5], a[6])
		if e == 0 {
			out[name] = "ok"
		} else {
			out[name] = e.Error()
		}
	}
	record("mount tmpfs", unix.Mount("tmpfs", "/tmp", "tmpfs", 0, ""))
	record("umount /proc", unix.Unmount("/proc", 0))
	// A fork that would create a user namespace: if the filter let it
	// through, the child exits at once.
	r, _, e := unix.RawSyscall6(unix.SYS_CLONE, unix.CLONE_NEWUSER|uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	if e == 0 && r == 0 {
		os.Exit(0)
	}
	if e == 0 {
		out["clone newuser"] = "ok"
	} else {
		out["clone newuser"] = e.Error()
	}

	// Network: nothing outside this namespace is reachable, by any route.
	dial := func(name, network, addr string) {
		c, err := net.DialTimeout(network, addr, 2*time.Second)
		if err == nil {
			_ = c.Close()
			out[name] = "connected"
			return
		}
		out[name] = "failed"
	}
	for _, v := range []string{"HOST_SINK", "HOST_SINK_DECIMAL", "HOST_SINK_HEX"} {
		if addr := os.Getenv("KEYLATCH_PROBE_" + v); addr != "" {
			dial("tcp "+v, "tcp", addr)
		}
	}
	dial("tcp public ipv4", "tcp", "1.1.1.1:80")
	dial("tcp public ipv6", "tcp", "[2606:4700:4700::1111]:80")
	dial("tcp metadata", "tcp", "169.254.169.254:80")
	dial("tcp 0.0.0.0", "tcp", "0.0.0.0:80")
	dial("tcp localhost alias", "tcp", "localhost.localdomain:80")
	dial("udp public", "udp", "1.1.1.1:53")
	_, err = net.LookupHost("exfil.example.invalid")
	out["dns lookup"] = fmt.Sprint(err != nil)
	record("icmp socket", func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}())
	record("netlink route", func() error {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		// Adding an address to a device needs CAP_NET_ADMIN, which the child lacks.
		return unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 0})
	}())
	ifaces, _ := net.Interfaces()
	var names []string
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	out["interfaces"] = strings.Join(names, ",")

	// Filesystem: state outside the project is absent, not masked.
	for _, name := range []string{"KEYLATCH_PROBE_STATE", "KEYLATCH_PROBE_SSH", "KEYLATCH_PROBE_DBUS", "KEYLATCH_PROBE_HOSTPROC"} {
		if p := os.Getenv(name); p != "" {
			_, err := os.ReadFile(p)
			record("read "+name, err)
		}
	}
	project := os.Getenv("KEYLATCH_PROBE_PROJECT")
	if project != "" {
		escape := func(name, link, target string) {
			_ = os.Remove(filepath.Join(project, link))
			if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
				out[name] = "symlink " + errnoName(err)
				return
			}
			_, err := os.ReadFile(filepath.Join(project, link))
			record(name, err)
		}
		if state := os.Getenv("KEYLATCH_PROBE_STATE"); state != "" {
			escape("symlink to state", "l1", state)
			escape("dotdot to state", "l2", strings.Repeat("../", 12)+strings.TrimPrefix(state, "/"))
		}
		escape("proc self root", "l3", "/proc/self/root/"+strings.TrimPrefix(os.Getenv("KEYLATCH_PROBE_STATE"), "/"))
		record("hardlink to /etc/passwd", os.Link("/etc/passwd", filepath.Join(project, "hl")))
		record("write /usr", os.WriteFile("/usr/keylatch-probe", []byte("x"), 0o600))
		record("write /etc", os.WriteFile("/etc/keylatch-probe", []byte("x"), 0o600))
		record("write project", os.WriteFile(filepath.Join(project, "written"), []byte(os.Getenv("KEYLATCH_PROBE_WRITE")), 0o600))
	}
	_, err = os.ReadDir("/")
	record("list /", err)
	_, err = os.ReadFile("/proc/1/mem")
	record("read /proc/1/mem", err)
	_, err = os.ReadFile("/proc/1/environ")
	record("read /proc/1/environ", err)
	_, err = os.ReadFile("/proc/kcore")
	out["read /proc/kcore"] = errnoName(err)
	record("write /proc/sys", os.WriteFile("/proc/sys/kernel/hostname", []byte("x"), 0o644))

	// A child that daemonizes must not outlive the run.
	if os.Getenv("KEYLATCH_PROBE_DAEMONIZE") == "1" {
		cmd := exec.Command("sleep", "600")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		_ = cmd.Start()
	}

	enc, _ := json.Marshal(out)
	fmt.Printf("PROBE-RESULT %s\n", enc)
	if mode := os.Getenv("KEYLATCH_PROBE_PRINT"); mode != "" {
		fmt.Println(os.Getenv(mode))
	}
}

func errnoName(err error) string {
	if err == nil {
		return "ok"
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return en.Error()
	}
	return err.Error()
}
