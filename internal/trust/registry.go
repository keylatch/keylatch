package trust

import (
	"fmt"
	"runtime"
	"sync"
)

// Factory is the constructor function type for RootOfTrust adapters.
// Each adapter package registers its factory via Register in an init() function.
type Factory func(spec RootSpec) (RootOfTrust, error)

var (
	registryMu sync.Map // map[RootType]Factory
)

// Register adds a Factory for the given RootType.
// Typically called from adapter init() functions.
// If a factory is already registered for the type, it is overwritten.
func Register(t RootType, f Factory) {
	registryMu.Store(t, f)
}

// Unregister removes the Factory for the given RootType.
// Intended for test cleanup only — do not call in production code.
func Unregister(t RootType) {
	registryMu.Delete(t)
}

// New constructs a RootOfTrust from the given spec by dispatching to the
// registered factory for spec.Type.
//
// Returns ErrRootUnavailable if no factory is registered for the type, or
// if the type is conditionally gated (e.g., RootSecureEnclave on non-darwin).
func New(spec RootSpec) (RootOfTrust, error) {
	// Conditional availability gate: Secure Enclave is darwin-only.
	if spec.Type == RootSecureEnclave && runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("%w: secure_enclave requires darwin", ErrRootUnavailable)
	}

	v, ok := registryMu.Load(spec.Type)
	if !ok {
		return nil, fmt.Errorf("%w: no factory registered for %q", ErrRootUnavailable, spec.Type)
	}
	f := v.(Factory)
	return f(spec)
}

// Available returns the list of RootTypes that have a registered factory.
// RootSecureEnclave is excluded on non-darwin systems.
func Available() []RootType {
	var types []RootType
	registryMu.Range(func(k, _ any) bool {
		t := k.(RootType)
		if t == RootSecureEnclave && runtime.GOOS != "darwin" {
			return true // skip on non-darwin
		}
		types = append(types, t)
		return true
	})
	return types
}
