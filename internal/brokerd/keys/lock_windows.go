package keys

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func mlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func munlock(b []byte) {
	if len(b) > 0 {
		_ = windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	}
}
