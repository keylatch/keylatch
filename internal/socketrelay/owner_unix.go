//go:build unix

package socketrelay

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkOwned refuses a socket path that another user could have planted or
// could replace: it must be a socket, not a symlink, owned by uid, in a
// directory owned by uid that others cannot write.
func checkOwned(path string, uid uint32) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("control socket: not a socket")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != uid {
		return errors.New("control socket: not owned by the current user")
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("control socket directory: %w", err)
	}
	st, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uid || dir.Mode().Perm()&0o022 != 0 {
		return errors.New("control socket directory: not owned by the current user or writable by others")
	}
	return nil
}
