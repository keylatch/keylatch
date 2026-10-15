package proc

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// The system calls are variables so tests can make them fail.
var (
	prctl     = unix.Prctl
	setrlimit = unix.Setrlimit
)

// harden clears the dumpable flag, which makes /proc/<pid>/environ and mem
// unreadable (and ptrace attach refused) for the process's own user, and sets
// the core dump limit to zero.
func harden() error {
	var errs []error
	if err := prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		errs = append(errs, fmt.Errorf("proc: clear dumpable flag: %w", err))
	}
	if err := setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		errs = append(errs, fmt.Errorf("proc: disable core dumps: %w", err))
	}
	return errors.Join(errs...)
}
