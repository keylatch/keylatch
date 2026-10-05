//go:build !linux && !darwin && !windows

package llmcontext

import "errors"

var errAncestryUnsupported = errors.New("process ancestry is not supported on this platform")

func readProcessInfo(int) (Process, error) { return Process{}, errAncestryUnsupported }

func parentPID(int) (int, error) { return 0, errAncestryUnsupported }
