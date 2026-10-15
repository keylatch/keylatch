package proc

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// harden refuses debugger attach with PT_DENY_ATTACH and disables core dumps.
func harden() error {
	var errs []error
	if err := unix.PtraceDenyAttach(); err != nil {
		errs = append(errs, fmt.Errorf("proc: deny debugger attach: %w", err))
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		errs = append(errs, fmt.Errorf("proc: disable core dumps: %w", err))
	}
	return errors.Join(errs...)
}
