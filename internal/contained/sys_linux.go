package contained

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// sysCalls is the set of privileged operations the namespace setup needs. The
// setup logic runs against this interface so tests can record it without
// creating namespaces.
type sysCalls interface {
	Mount(src, dst, fstype string, flags uintptr, data string) error
	Unmount(dst string, flags int) error
	PivotRoot(newRoot, putOld string) error
	Chdir(dir string) error
	MkdirAll(path string, mode os.FileMode) error
	WriteFile(path string, data []byte, mode os.FileMode) error
	Symlink(target, link string) error
	Readlink(path string) (string, error)
	Lstat(path string) (os.FileInfo, error)
	Remove(path string) error
	// MountFlags returns the mount flags of the filesystem holding path, in
	// the MS_* encoding, so a remount keeps the flags the kernel locks.
	MountFlags(path string) (uintptr, error)
	SetHostname(name string) error
	LoopbackUp() error
}

type hostSys struct{}

func (hostSys) Mount(src, dst, fstype string, flags uintptr, data string) error {
	if err := unix.Mount(src, dst, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %s on %s: %w", orDash(src), dst, err)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (hostSys) Unmount(dst string, flags int) error { return unix.Unmount(dst, flags) }
func (hostSys) PivotRoot(newRoot, putOld string) error {
	return unix.PivotRoot(newRoot, putOld)
}
func (hostSys) Chdir(dir string) error                       { return unix.Chdir(dir) }
func (hostSys) MkdirAll(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }
func (hostSys) WriteFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}
func (hostSys) Symlink(target, link string) error      { return os.Symlink(target, link) }
func (hostSys) Readlink(path string) (string, error)   { return os.Readlink(path) }
func (hostSys) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }
func (hostSys) Remove(path string) error               { return os.Remove(path) }
func (hostSys) SetHostname(name string) error          { return unix.Sethostname([]byte(name)) }

// inheritedMountFlags are the statfs flags that equal their MS_* counterparts.
const inheritedMountFlags = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC | unix.ST_NOATIME | unix.ST_NODIRATIME | unix.ST_RELATIME

func (hostSys) MountFlags(path string) (uintptr, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uintptr(st.Flags) & inheritedMountFlags, nil //nolint:gosec // G115: statfs flags are small non-negative bit masks
}

func (hostSys) LoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	ifr.SetUint16(unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
