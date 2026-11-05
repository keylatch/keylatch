package control

import (
	"golang.org/x/sys/windows"
)

func init() {
	processSID = func(pid uint32) (string, error) {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return "", err
		}
		defer func() { _ = windows.CloseHandle(h) }()
		var tok windows.Token
		if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
			return "", err
		}
		defer func() { _ = tok.Close() }()
		user, err := tok.GetTokenUser()
		if err != nil {
			return "", err
		}
		return user.User.Sid.String(), nil
	}
}
