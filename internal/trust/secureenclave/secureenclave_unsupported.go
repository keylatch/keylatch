//go:build !darwin

// Package secureenclave provides a Secure Enclave trust adapter.
// On non-darwin platforms all operations return ErrRootUnavailable.
package secureenclave

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/trust"
)

// Options configures the Secure Enclave adapter (no-op on non-darwin).
type Options struct {
	Label        string
	PresenceMode string
	Namespace    string
}

// Adapter is an unsupported stub on non-darwin platforms.
type Adapter struct{}

// New always returns ErrRootUnavailable on non-darwin platforms.
func New(_ Options) (*Adapter, error) {
	return nil, fmt.Errorf("%w: Secure Enclave is only available on darwin", trust.ErrRootUnavailable)
}
