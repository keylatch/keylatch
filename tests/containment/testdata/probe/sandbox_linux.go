package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// ptrace tries to attach to a process and to read its memory.
func ptrace(pidArg string) {
	pid, _ := strconv.Atoi(pidArg)
	report := func(route string, err error) {
		if err != nil {
			fmt.Printf("%s=blocked\n", route)
			return
		}
		fmt.Printf("%s=reached\n", route)
	}
	report("ptrace-attach", syscall.PtraceAttach(pid))
	_, err := os.ReadFile(fmt.Sprintf("/proc/%d/mem", pid))
	report("proc-mem", err)
	_, err = os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	report("proc-environ", err)
	local := []unix.Iovec{{Base: new(byte), Len: 1}}
	remote := []unix.RemoteIovec{{Base: 0x1000, Len: 1}}
	_, err = unix.ProcessVMReadv(pid, local, remote, 0)
	report("process-vm-readv", err)
}

// nested tries the ways a child can build or leave a sandbox.
func nested() {
	report := func(route string, err error) {
		if err != nil {
			fmt.Printf("%s=blocked\n", route)
			return
		}
		fmt.Printf("%s=reached\n", route)
	}
	report("unshare-user", unix.Unshare(unix.CLONE_NEWUSER))
	report("unshare-mount", unix.Unshare(unix.CLONE_NEWNS))
	report("mount-tmpfs", unix.Mount("tmpfs", "/tmp", "tmpfs", 0, ""))
	report("chroot", unix.Chroot("/tmp"))
	report("pivot-root", unix.PivotRoot("/tmp", "/tmp"))
	_, _, e := unix.Syscall(unix.SYS_IO_URING_SETUP, 8, 0, 0)
	report("io-uring", errnoErr(e))
	_, _, e = unix.Syscall(unix.SYS_BPF, 0, 0, 0)
	report("bpf", errnoErr(e))
	_, _, e = unix.Syscall(unix.SYS_KEYCTL, 0, 0, 0)
	report("keyctl", errnoErr(e))
	_, err := os.ReadFile("/proc/self/root/etc/shadow")
	report("proc-self-root-shadow", err)
}

func errnoErr(e unix.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}

// traverse links and walks out of a directory toward a protected file.
func traverse(dir, target string) {
	report := func(route string, err error) {
		if err != nil {
			fmt.Printf("%s=blocked\n", route)
			return
		}
		fmt.Printf("%s=reached\n", route)
	}
	link := filepath.Join(dir, "escape-link")
	_ = os.Remove(link)
	if err := os.Symlink(target, link); err == nil {
		_, err = os.ReadFile(link)
		report("symlink", err)
	} else {
		report("symlink", err)
	}
	_, err := os.ReadFile(filepath.Join(dir, "..", "..", "..", "..", "..", "..", "..", "..", target))
	report("dotdot", err)
	hard := filepath.Join(dir, "escape-hardlink")
	_ = os.Remove(hard)
	err = os.Link(target, hard)
	if err == nil {
		_, err = os.ReadFile(hard)
	}
	report("hardlink", err)
	_, err = os.ReadFile("/proc/self/root" + target)
	report("proc-self-root", err)
}
