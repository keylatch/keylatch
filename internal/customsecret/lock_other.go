//go:build !(linux || darwin || freebsd || netbsd || openbsd || windows)

package customsecret

import "errors"

// lockFile refuses where no file lock is available: the rules are never changed unlocked.
func lockFile(string) (func(), error) {
	return nil, errors.New("file locking is not supported on this platform")
}
