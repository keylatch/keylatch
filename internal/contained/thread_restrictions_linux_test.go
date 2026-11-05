//go:build linux && (amd64 || arm64)

package contained

// These tests apply seccomp, Landlock and no_new_privs to real OS threads of
// the test process. The restrictions belong to a thread and pass to threads it
// creates, so the file sorts last and its tests start no processes.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// onDisposableThread runs fn on a locked OS thread that exits afterwards: a
// goroutine that returns while locked takes its thread with it.
func onDisposableThread(t *testing.T, fn func() error) error {
	t.Helper()
	var wg sync.WaitGroup
	var err error
	wg.Add(1)
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		err = fn()
	}()
	wg.Wait()
	return err
}

func TestInstalledFilterRefusesPtraceOnTheRealKernel(t *testing.T) {
	var ptraceErr, getpidErr error
	err := onDisposableThread(t, func() error {
		if err := (hostRestrictor{}).NoNewPrivs(); err != nil {
			return err
		}
		if err := (hostRestrictor{}).Seccomp(defaultFilter(false)); err != nil {
			return err
		}
		_, _, e := unix.Syscall(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0)
		if e != 0 {
			ptraceErr = e
		}
		if unix.Getpid() <= 0 {
			getpidErr = errors.New("getpid failed")
		}
		return nil
	})
	if err != nil {
		t.Skipf("seccomp is unavailable here: %v", err)
	}
	assert.ErrorIs(t, ptraceErr, unix.EPERM)
	assert.NoError(t, getpidErr)
}

func TestLandlockRestrictsTheRealKernel(t *testing.T) {
	abi := (hostRestrictor{}).LandlockABI()
	if abi < 1 {
		t.Skip("the kernel has no Landlock")
	}
	allowed, denied := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(allowed, "f"), []byte("x"), 0o600))
	var readAllowed, writeAllowed, writeDenied error
	err := onDisposableThread(t, func() error {
		if err := (hostRestrictor{}).NoNewPrivs(); err != nil {
			return err
		}
		plan := newLandlockPlan(abi, []string{"/usr", "/lib", "/lib64", "/proc", "/dev", "/etc"}, []string{allowed}, nil)
		if err := (hostRestrictor{}).Landlock(plan); err != nil {
			return err
		}
		_, readAllowed = os.ReadFile(filepath.Join(allowed, "f"))
		writeAllowed = os.WriteFile(filepath.Join(allowed, "g"), []byte("x"), 0o600)
		writeDenied = os.WriteFile(filepath.Join(denied, "g"), []byte("x"), 0o600)
		return nil
	})
	require.NoError(t, err)
	assert.NoError(t, readAllowed)
	assert.NoError(t, writeAllowed)
	assert.Error(t, writeDenied, "a directory outside the rules is not writable")
}

func TestLandlockApplyReportsBadRules(t *testing.T) {
	abi := landlockABI()
	if abi < 1 {
		t.Skip("the kernel has no Landlock")
	}
	err := onDisposableThread(t, func() error {
		if err := (hostRestrictor{}).NoNewPrivs(); err != nil {
			return err
		}
		plan := landlockPlan{abi: abi, fsHandled: fsMask(abi), paths: []pathRule{{"/nonexistent/keylatch", 1}}}
		return plan.apply()
	})
	assert.Error(t, err)
}

func TestDropCapabilitiesOnAnUnprivilegedThread(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "cap_last_cap")
	for _, drop := range []func() error{
		func() error { return (hostRestrictor{}).DropCapabilities() },
		func() error { return dropCapabilities(missing) },
	} {
		err := onDisposableThread(t, drop)
		// An unprivileged thread owns no capabilities; emptying the sets
		// either succeeds or is refused for the bounding set alone.
		if err != nil {
			assert.ErrorContains(t, err, "capabilities")
		}
	}
}
