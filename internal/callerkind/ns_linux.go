//go:build linux

package callerkind

import (
	"fmt"
	"os"
)

// SharesNamespaces reports whether pid is in the same PID, mount, user and
// network namespaces as this process. A process that cannot be inspected is
// treated as outside them.
func SharesNamespaces(pid int) bool {
	if pid <= 0 {
		return false
	}
	for _, ns := range []string{"pid", "mnt", "user", "net"} {
		if !sameNamespace(ns, pid) {
			return false
		}
	}
	return true
}

func sameNamespace(ns string, pid int) bool {
	mine, err := os.Stat("/proc/self/ns/" + ns)
	if err != nil {
		return false
	}
	theirs, err := os.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, ns))
	if err != nil {
		return false
	}
	return os.SameFile(mine, theirs)
}
