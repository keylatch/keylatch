//go:build !windows

package customsecret

import "os"

func replaceFile(from, to string) error { return os.Rename(from, to) }
