package hook

import "syscall"

// platformExpandShortNames returns the long form of a path with 8.3 short
// names; a path that does not exist, or any failure, comes back unchanged.
func platformExpandShortNames(p string) string {
	from, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	n, err := syscall.GetLongPathName(from, nil, 0)
	if err != nil || n == 0 {
		return p
	}
	buf := make([]uint16, n)
	n, err = syscall.GetLongPathName(from, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n > uint32(len(buf)) {
		return p
	}
	return syscall.UTF16ToString(buf[:n])
}
