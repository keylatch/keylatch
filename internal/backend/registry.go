// Package backend defines the Backend interface and shared types.
// registry.go provides a self-registration factory registry modelled on database/sql.
package backend

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Factory is a function that constructs a Backend from a BackendConfig.
type Factory func(ctx context.Context, cfg BackendConfig) (Backend, error)

// BackendConfig carries the name and opaque settings passed to a Factory.
type BackendConfig struct {
	// Name is the backend identifier (e.g. "file", "keychain", "op", "bw").
	Name string

	// Settings is an opaque map of backend-specific configuration keys.
	// Each backend factory is responsible for decoding and validating it.
	Settings map[string]interface{}
}

// Registry is a thread-safe map from backend name to Factory.
// Use Default for the process-wide registry.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// ErrAlreadyRegistered is returned by Register when a name is already in use.
type ErrAlreadyRegistered struct {
	Name string
}

func (e ErrAlreadyRegistered) Error() string {
	return fmt.Sprintf("backend registry: %q is already registered", e.Name)
}

// NewRegistry returns an empty, ready-to-use Registry.
// Most callers should use Default; this constructor is provided for tests
// that need an isolated registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Register adds f under name. Returns ErrAlreadyRegistered if name is taken.
func (r *Registry) Register(name string, f Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; exists {
		return ErrAlreadyRegistered{Name: name}
	}
	r.factories[name] = f
	return nil
}

// Get returns the Factory registered under name, or (nil, false) if absent.
func (r *Registry) Get(name string) (Factory, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.factories[name]
	return f, ok
}

// List returns a sorted copy of all registered backend names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Default is the process-wide backend registry. Backends self-register here
// via init() functions (import side-effect pattern, like database/sql drivers).
var Default = &Registry{factories: make(map[string]Factory)}

// StripNonStringSettings returns a copy of m with only string or nil values,
// stripping opaque non-config keys such as env-lookup functions.
// Use this before passing Settings to mapstructure.Decode so that function
// values (e.g. the "env" key) do not trigger "unused key" errors.
func StripNonStringSettings(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		switch v.(type) {
		case string, nil:
			out[k] = v
		}
	}
	return out
}
