//go:build unix

package connpolicy

import (
	"fmt"
	"io/fs"
	"syscall"
)

// rootOwnedAndClosed fails unless root owns path and nobody else can write it.
func rootOwnedAndClosed(path string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s is not owned by root", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by someone other than root", path)
	}
	return nil
}
