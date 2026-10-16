//go:build unix

package childstore

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInheritedDescriptorIsMarkedCloseOnExec(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := int(r.Fd())
	// An inherited descriptor starts without the flag.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	if flags, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); flags&unix.FD_CLOEXEC != 0 {
		t.Fatal("setup: the flag is set")
	}
	markCloseOnExec(fd)
	if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("the descriptor can still be inherited: flags %d, %v", flags, err)
	}
}

func TestDescriptorFrom(t *testing.T) {
	if fd, ok := descriptorFrom("3"); !ok || fd != 3 {
		t.Fatalf("3 = %d, %v", fd, ok)
	}
	for _, bad := range []string{"", "x", "2", "-4"} {
		if _, ok := descriptorFrom(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
