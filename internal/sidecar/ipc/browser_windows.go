package ipc

import (
	"net/url"

	"golang.org/x/sys/windows"
)

var shellExecute = windows.ShellExecute

func openBrowser(parsed *url.URL) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(parsed.String())
	if err != nil {
		return err
	}
	return shellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL)
}
