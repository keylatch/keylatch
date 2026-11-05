//go:build !linux && !darwin && !windows

package brokerd

import "github.com/keylatch/keylatch/internal/control"

// Identify is unavailable on this platform: the system broker runs on Linux,
// macOS and Windows.
func Identify(control.Conn) (*Identity, error) { return nil, ErrUnsupported }
