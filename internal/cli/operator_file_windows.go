package cli

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// readOperatorFile reads the operator's default config file. Windows has no
// mode bits, so ownership is what is checked: the file must be a regular
// file (not a link) owned by the current user, or by a group this token may
// assign as owner (an elevated administrator's files are owned by the
// Administrators group by default).
func readOperatorFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := ownedByCurrentUser(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path) //nolint:gosec // G304: path is the operator's default config file
}

func ownedByCurrentUser(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: read owner: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s: file has no owner", path)
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user: %w", err)
	}
	if owner.Equals(user.User.Sid) {
		return nil
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return fmt.Errorf("read current groups: %w", err)
	}
	for _, g := range groups.AllGroups() {
		if g.Attributes&windows.SE_GROUP_OWNER != 0 && g.Attributes&windows.SE_GROUP_ENABLED != 0 && owner.Equals(g.Sid) {
			return nil
		}
	}
	return errors.New(path + " is not owned by the current user")
}
