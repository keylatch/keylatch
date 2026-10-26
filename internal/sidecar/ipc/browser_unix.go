//go:build !windows

package ipc

import (
	"net/url"
	"runtime"
)

func openBrowser(parsed *url.URL) error {
	cmd, err := browserCommand(runtime.GOOS, parsed)
	if err != nil {
		return err
	}
	return cmd.Start()
}
