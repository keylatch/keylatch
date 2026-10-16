package contained

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// initBinaryPath is where the helper binary appears inside the new root, so the
// second stage can be started after the root has been replaced.
const initBinaryPath = "/.keylatch-init"

// systemDirs appear read-only at the same path when the host has them. A
// directory that is a symlink (merged /usr) is recreated as the same symlink.
var systemDirs = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// etcEntries are the only parts of /etc the child sees: users and groups for
// name lookups, the dynamic linker's cache and the trust store. Everything
// else, including Keylatch's own configuration, is absent.
var etcEntries = []string{
	"passwd", "group", "nsswitch.conf", "ld.so.cache", "ld.so.conf", "ld.so.conf.d", "ssl", "ca-certificates",
	"pki", "alternatives", "localtime", "terminfo",
}

const etcHosts = "127.0.0.1 localhost\n::1 localhost\n"

var deviceNodes = []string{"null", "zero", "full", "random", "urandom", "tty"}

// maskedProc are procfs files that disclose the host or allow tuning it.
var maskedProc = []string{"kcore", "keys", "timer_list", "sched_debug", "scsi"}
var readOnlyProc = []string{"sys", "sysrq-trigger", "irq", "bus"}

// sandboxPaths lists what the child may read and what it may write inside the
// new root. The mounts and the Landlock rules are both built from it.
func sandboxPaths(s Spec) (ro, rw []string) {
	ro = append(ro, systemDirs...)
	ro = append(ro, "/etc", EgressMount)
	ro = append(ro, s.ReadOnly...)
	rw = append(rw, s.Project, s.Home, "/tmp", "/dev", "/proc")
	rw = append(rw, s.ReadWrite...)
	return ro, rw
}

type bindSpec struct {
	src, dst string
	rw       bool
	optional bool
}

type rootBuilder struct {
	sys  sysCalls
	root string
}

func (b rootBuilder) at(dst string) string { return filepath.Join(b.root, dst) }

func (b rootBuilder) tmpfs(dst string, opts string) error {
	if err := b.sys.MkdirAll(b.at(dst), 0o755); err != nil {
		return err
	}
	return b.sys.Mount("tmpfs", b.at(dst), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, opts)
}

// bind mounts src at dst inside the new root. A missing source is skipped
// when optional. A symlink source is recreated as a symlink.
func (b rootBuilder) bind(src, dst string, rw, optional bool) error {
	info, err := b.sys.Lstat(src)
	if err != nil {
		if optional && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("mount source %s: %w", src, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := b.sys.Readlink(src)
		if err != nil {
			return err
		}
		if err := b.sys.MkdirAll(filepath.Dir(b.at(dst)), 0o755); err != nil {
			return err
		}
		return b.sys.Symlink(target, b.at(dst))
	}
	if info.IsDir() {
		err = b.sys.MkdirAll(b.at(dst), 0o755)
	} else {
		if err = b.sys.MkdirAll(filepath.Dir(b.at(dst)), 0o755); err == nil {
			err = b.sys.WriteFile(b.at(dst), nil, 0o644)
		}
	}
	if err != nil {
		return err
	}
	if err := b.sys.Mount(src, b.at(dst), "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	locked, err := b.sys.MountFlags(src)
	if err != nil {
		return err
	}
	flags := uintptr(unix.MS_BIND|unix.MS_REMOUNT|unix.MS_NOSUID|unix.MS_NODEV) | locked
	if !rw {
		flags |= unix.MS_RDONLY
	}
	return b.sys.Mount("", b.at(dst), "", flags, "")
}

func (b rootBuilder) devices() error {
	if err := b.sys.MkdirAll(b.at("/dev"), 0o755); err != nil {
		return err
	}
	if err := b.sys.Mount("tmpfs", b.at("/dev"), "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=0755,size=64k"); err != nil {
		return err
	}
	for _, n := range deviceNodes {
		src := "/dev/" + n
		if _, err := b.sys.Lstat(src); err != nil {
			continue
		}
		dst := b.at(src)
		if err := b.sys.WriteFile(dst, nil, 0o666); err != nil {
			return err
		}
		if err := b.sys.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	// A private devpts and shm are conveniences; a host without them still runs.
	if err := b.sys.MkdirAll(b.at("/dev/pts"), 0o755); err == nil {
		if err := b.sys.Mount("devpts", b.at("/dev/pts"), "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err == nil {
			_ = b.sys.Symlink("pts/ptmx", b.at("/dev/ptmx"))
		}
	}
	if err := b.sys.MkdirAll(b.at("/dev/shm"), 0o1777); err == nil {
		_ = b.sys.Mount("tmpfs", b.at("/dev/shm"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777,size=64m")
	}
	for link, target := range map[string]string{"fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := b.sys.Symlink(target, b.at("/dev/"+link)); err != nil {
			return err
		}
	}
	return nil
}

// setupRoot assembles the new root on spec.RootDir and makes it the process's
// root. It runs inside the new mount namespace.
func setupRoot(sys sysCalls, spec Spec, helper string) error {
	b := rootBuilder{sys: sys, root: spec.RootDir}
	if err := sys.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := sys.Mount("tmpfs", spec.RootDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=4m"); err != nil {
		return err
	}
	// Scratch filesystems first: a bind mount at a path below one of them must
	// not be hidden by it.
	for _, t := range []struct{ dst, opts string }{
		{"/tmp", "mode=1777"}, {spec.Home, "mode=0700"}, {"/run", "mode=0755,size=1m"},
	} {
		if err := b.tmpfs(t.dst, t.opts); err != nil {
			return err
		}
	}
	if err := sys.MkdirAll(b.at("/etc"), 0o755); err != nil {
		return err
	}
	if err := sys.WriteFile(b.at("/etc/hosts"), []byte(etcHosts), 0o644); err != nil {
		return err
	}
	var binds []bindSpec
	add := func(src, dst string, rw, optional bool) {
		binds = append(binds, bindSpec{src, dst, rw, optional})
	}
	for _, d := range systemDirs {
		add(d, d, false, true)
	}
	for _, e := range etcEntries {
		add("/etc/"+e, "/etc/"+e, false, true)
	}
	for _, p := range spec.ReadOnly {
		add(p, p, false, true)
	}
	add(spec.EgressDir, EgressMount, false, false)
	add(spec.Project, spec.Project, true, false)
	for _, p := range spec.ReadWrite {
		add(p, p, true, true)
	}
	add(helper, initBinaryPath, false, false)
	slices.SortStableFunc(binds, func(x, y bindSpec) int {
		return strings.Count(x.dst, "/") - strings.Count(y.dst, "/")
	})
	for _, m := range binds {
		if err := b.bind(m.src, m.dst, m.rw, m.optional); err != nil {
			return err
		}
	}
	if err := b.devices(); err != nil {
		return err
	}
	// procfs must be mounted while the host's /proc is still visible: the
	// kernel allows a new instance only where an unobscured one exists.
	if err := sys.MkdirAll(b.at("/proc"), 0o555); err != nil {
		return err
	}
	if err := sys.Mount("proc", b.at("/proc"), "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	return pivot(sys, spec.RootDir)
}

func pivot(sys sysCalls, root string) error {
	old := filepath.Join(root, ".old")
	if err := sys.MkdirAll(old, 0o700); err != nil {
		return err
	}
	if err := sys.PivotRoot(root, old); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := sys.Chdir("/"); err != nil {
		return err
	}
	if err := sys.Unmount("/.old", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount the old root: %w", err)
	}
	if err := sys.Remove("/.old"); err != nil {
		return err
	}
	for _, name := range readOnlyProc {
		p := "/proc/" + name
		if _, err := sys.Lstat(p); err != nil {
			continue
		}
		if err := sys.Mount(p, p, "", unix.MS_BIND, ""); err == nil {
			_ = sys.Mount("", p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
		}
	}
	for _, name := range maskedProc {
		p := "/proc/" + name
		info, err := sys.Lstat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			_ = sys.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4k")
		} else {
			_ = sys.Mount("/dev/null", p, "", unix.MS_BIND, "")
		}
	}
	return nil
}
