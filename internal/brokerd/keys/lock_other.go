//go:build !unix

package keys

import "errors"

func mlock([]byte) error { return errors.New("memory locking is not available on this platform") }

func munlock([]byte) {}
