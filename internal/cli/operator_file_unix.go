//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// readOperatorFile reads path only if it is a regular file, not a symlink,
// owned by the effective user and not writable by group or others.
func readOperatorFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: path is the operator's default config file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s is writable by group or others", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return nil, errors.New(path + " is not owned by the current user")
	}
	return io.ReadAll(f)
}
