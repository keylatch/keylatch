//go:build linux && !amd64 && !arm64

package contained

import (
	"errors"

	"golang.org/x/sys/unix"
)

var errNoProgram = errors.New("contained: no seccomp filter exists for this architecture")

func defaultFilter(bool) []unix.SockFilter { return nil }

func installFilter([]unix.SockFilter) error { return errNoProgram }
