//go:build unix

package keys

import "golang.org/x/sys/unix"

func mlock(b []byte) error { return unix.Mlock(b) }

func munlock(b []byte) { _ = unix.Munlock(b) }
