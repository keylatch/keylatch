//go:build windows

package keyring

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func setDACL(t *testing.T, path string, sids ...*windows.SID) {
	t.Helper()
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
}

func TestWindowsOwnerOnlyDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	setDACL(t, path, user.User.Sid)
	if err := checkPrivateFile(path, info); err != nil {
		t.Fatalf("an owner-only DACL was refused: %v", err)
	}

	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, user.User.Sid, everyone)
	err = checkPrivateFile(path, info)
	if err == nil || !strings.Contains(err.Error(), everyone.String()) {
		t.Fatalf("a DACL that grants Everyone access was accepted: %v", err)
	}
	if _, err := loadFile(path); !errors.Is(err, ErrKeyringCorrupt) {
		t.Fatalf("loadFile accepted a keyring file readable by Everyone: %v", err)
	}
}

func TestWindowsLockFileEx(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	open := func() *os.File {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	holder, other := open(), open()
	tryLock := func(f *os.File) error {
		return windows.LockFileEx(windows.Handle(f.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, lockedBytes, 0, new(windows.Overlapped))
	}

	if err := flockExclusive(holder); err != nil {
		t.Fatal(err)
	}
	if err := tryLock(other); !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("a second handle took the lock while it was held: %v", err)
	}
	if err := flockUnlock(holder); err != nil {
		t.Fatal(err)
	}
	if err := tryLock(other); err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
}
