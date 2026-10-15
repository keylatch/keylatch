//go:build !linux && !darwin && !windows

package audit

import "errors"

// OSLogAnchor is unavailable on this platform; anchors are not written.
func OSLogAnchor(Head) error { return errors.New("audit anchor: no OS log on this platform") }
