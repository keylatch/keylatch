//go:build linux

package brokerd

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const fakeStat = "4242 (agent) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 555 1000 100 18446744073709551615"

// fakeSys replaces the kernel calls so a test can stage a recycled PID.
func fakeSys(t *testing.T, stat *string, signalErr *error) (closed *int) {
	t.Helper()
	prev := sys
	n := 0
	sys = system{
		readFile: func(p string) ([]byte, error) {
			switch filepath.Base(p) {
			case "stat":
				return []byte(*stat), nil
			case "cgroup":
				return []byte("0::/user.slice/user-1000.slice/app.slice/term.scope\n"), nil
			}
			return nil, os.ErrNotExist
		},
		pidfdOpen:   func(int) (int, error) { return 77, nil },
		pidfdSignal: func(int) error { return *signalErr },
		closeFD:     func(int) { n++ },
		peerCred:    func(*net.UnixConn) (uint32, int, error) { return 1000, 4242, nil },
		peerPidfd:   func(*net.UnixConn) (int, error) { return -1, errors.New("old kernel") },
	}
	t.Cleanup(func() { sys = prev })
	return &n
}

func TestPidReuseRejected(t *testing.T) {
	stat, signalErr := fakeStat, error(nil)
	closed := fakeSys(t, &stat, &signalErr)

	id, err := Identify(nil)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if id.UID != 1000 || id.PID != 4242 || id.Start != "555" || id.Cgroup != "/user.slice/user-1000.slice/app.slice/term.scope" {
		t.Fatalf("identity = %+v", id)
	}
	if err := id.Verify(); err != nil {
		t.Fatalf("Verify of the same process: %v", err)
	}

	// The PID now belongs to a different process: same number, new start time.
	stat = "4242 (other) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 556 1000 100 18446744073709551615"
	if err := id.Verify(); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("Verify after PID reuse = %v, want ErrPeerGone", err)
	}

	// The process exited: the pidfd no longer signals.
	stat, signalErr = fakeStat, errors.New("no such process")
	if err := id.Verify(); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("Verify after exit = %v, want ErrPeerGone", err)
	}

	id.Close()
	if *closed != 1 {
		t.Fatalf("pidfd closed %d times, want 1", *closed)
	}
}

func TestIdentifyRefusals(t *testing.T) {
	stat, signalErr := fakeStat, error(nil)
	fakeSys(t, &stat, &signalErr)

	sys.peerCred = func(*net.UnixConn) (uint32, int, error) { return 1000, 0, nil }
	if _, err := Identify(nil); !errors.Is(err, ErrNoPID) {
		t.Fatalf("a peer in another PID namespace = %v, want ErrNoPID", err)
	}
	sys.peerCred = func(*net.UnixConn) (uint32, int, error) { return 0, 0, errors.New("no creds") }
	if _, err := Identify(nil); err == nil {
		t.Fatal("a failing SO_PEERCRED must fail")
	}
	sys.peerCred = func(*net.UnixConn) (uint32, int, error) { return 1000, 4242, nil }
	sys.pidfdOpen = func(int) (int, error) { return -1, errors.New("gone") }
	if _, err := Identify(nil); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("a process that cannot be pinned = %v, want ErrPeerGone", err)
	}
	sys.pidfdOpen = func(int) (int, error) { return 5, nil }
	stat = "garbage"
	if _, err := Identify(nil); err == nil {
		t.Fatal("an unreadable start time must fail")
	}
	sys.readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	if _, err := Identify(nil); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("a vanished /proc entry = %v, want ErrPeerGone", err)
	}

	// A peer that exits between the first read and the final check is refused.
	stat, signalErr = fakeStat, errors.New("exited")
	sys.readFile = func(p string) ([]byte, error) { return []byte(stat), nil }
	if _, err := Identify(nil); !errors.Is(err, ErrPeerGone) {
		t.Fatalf("a peer that exited during identification = %v, want ErrPeerGone", err)
	}
}

func TestPeerPidfdPrefersTheKernelPidfd(t *testing.T) {
	stat, signalErr := fakeStat, error(nil)
	fakeSys(t, &stat, &signalErr)
	opened := false
	sys.peerPidfd = func(*net.UnixConn) (int, error) { return 9, nil }
	sys.pidfdOpen = func(int) (int, error) { opened = true; return 1, nil }
	id, err := Identify(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer id.Close()
	if opened {
		t.Fatal("pidfd_open must not run when SO_PEERPIDFD supplied the descriptor")
	}
}

// TestIdentifyRealPeer identifies this very process through a real socket pair.
func TestIdentifyRealPeer(t *testing.T) {
	server, _ := pair(t)
	id, err := Identify(server)
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	defer id.Close()
	if id.UID != uint32(os.Getuid()) || id.PID != os.Getpid() { //nolint:gosec // G115: uid is non-negative
		t.Fatalf("identity = %+v, want this process", id)
	}
	want, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip("no /proc/self/cgroup")
	}
	if id.Cgroup != ParseCgroup(string(want)) {
		t.Fatalf("Cgroup = %q, want %q", id.Cgroup, ParseCgroup(string(want)))
	}
	if _, err := strconv.Atoi(id.Start); err != nil {
		t.Fatalf("Start = %q is not a number", id.Start)
	}
	if err := id.Verify(); err != nil {
		t.Fatalf("a live peer must verify: %v", err)
	}
}
