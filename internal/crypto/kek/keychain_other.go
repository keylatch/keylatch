//go:build !darwin

package kek

import "fmt"

// KeychainKEK is not supported on non-darwin platforms.
func KeychainKEK(_ string) (KEK, error) {
	return nil, fmt.Errorf("%w: KeychainKEK is only available on macOS", ErrKEKUnavailable)
}
