package proc

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process mitigation policy kinds and flags (winnt.h).
const (
	processExtensionPointDisablePolicy = 6
	processImageLoadPolicy             = 10

	disableExtensionPoints = 1 << 0

	noRemoteImages             = 1 << 0
	noLowMandatoryLabelImages  = 1 << 1
	preferSystem32Images       = 1 << 2
	imageLoadRestrictionsFlags = noRemoteImages | noLowMandatoryLabelImages | preferSystem32Images
)

var procSetProcessMitigationPolicy = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetProcessMitigationPolicy")

func setMitigation(kind uintptr, flags uint32) error {
	r, _, err := procSetProcessMitigationPolicy.Call(kind, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags)) //nolint:gosec // G103: the policy struct is one DWORD of flags
	if r == 0 {
		return err
	}
	return nil
}

// harden restricts what can be injected into the process (extension points,
// remote and low-integrity images) and keeps Windows Error Reporting from
// raising crash dialogs that write a dump.
func harden() error {
	var errs []error
	if err := setMitigation(processExtensionPointDisablePolicy, disableExtensionPoints); err != nil {
		errs = append(errs, fmt.Errorf("proc: disable extension points: %w", err))
	}
	if err := setMitigation(processImageLoadPolicy, imageLoadRestrictionsFlags); err != nil {
		errs = append(errs, fmt.Errorf("proc: restrict image loading: %w", err))
	}
	windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX)
	return errors.Join(errs...)
}
