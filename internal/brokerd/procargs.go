package brokerd

import (
	"bytes"
	"errors"
)

// execPathOfProcArgs returns the executable path from a kern.procargs2 dump: a
// 4-byte argc followed by the NUL-terminated executable path.
func execPathOfProcArgs(raw []byte) (string, error) {
	if len(raw) < 5 {
		return "", errors.New("brokerd: short kern.procargs2")
	}
	rest := raw[4:]
	end := bytes.IndexByte(rest, 0)
	if end <= 0 {
		return "", errors.New("brokerd: kern.procargs2 has no executable path")
	}
	return string(rest[:end]), nil
}
