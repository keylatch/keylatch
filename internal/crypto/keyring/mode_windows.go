//go:build windows

package keyring

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enforcePrivateFileMode is false: Windows files carry no permission bits a
// test could set wrongly. checkPrivateFile reads the DACL instead.
const enforcePrivateFileMode = false

// checkPrivateFile requires the keyring file to be owned by the current user
// (or the Administrators group) and its DACL to grant access to nobody but the
// current user, SYSTEM and Administrators. A file that inherits a permissive
// DACL from its directory fails the check.
func checkPrivateFile(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the security descriptor: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the current user: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	trusted := []*windows.SID{user.User.Sid, admins, system}

	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("the file has no owner")
	}
	if !owner.Equals(user.User.Sid) && !owner.Equals(admins) {
		return fmt.Errorf("is owned by %s, not the current user", owner)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read the DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("has no DACL, which gives every user full access")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read DACL entry %d: %w", i, err)
		}
		// Deny entries only narrow access; only grants matter.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !containsSID(trusted, sid) {
			return fmt.Errorf("its DACL grants access to %s", sid)
		}
	}
	return nil
}

func containsSID(list []*windows.SID, sid *windows.SID) bool {
	for _, s := range list {
		if s.Equals(sid) {
			return true
		}
	}
	return false
}
