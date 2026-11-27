//go:build windows

package customsecret

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// replaceFile renames over path; Windows refuses while another handle (a reader,
// a scanner) has the target open, so it retries briefly.
func replaceFile(from, to string) error {
	var err error
	for i := 0; i < 20; i++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return err
		}
		time.Sleep(time.Duration(i+1) * 5 * time.Millisecond)
	}
	return err
}
