package registry

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/keylatch/keylatch/internal/template"
)

// ErrProviderNotFound is returned when a provider slug is not in the registry.
var ErrProviderNotFound = errors.New("registry: provider not found")

// catalog is the in-memory map of provider slug → ConnectionTemplate.
// It is populated during init() from compiled-in Core v1 structs.
var (
	mu      sync.RWMutex
	catalog = map[string]ConnectionTemplate{}
)

// Reset clears the catalog, removing all registered templates.
// It acquires the write lock and replaces the map with an empty one.
// Call this before re-loading templates (e.g. from Reload or InitFromConfig).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	catalog = map[string]ConnectionTemplate{}
}

// Register adds a template to the catalog idempotently.
// Returns an error if a different template with the same slug is already registered.
// Used by InitFromConfig to populate the catalog from YAML-loaded templates.
func Register(t ConnectionTemplate) error {
	mu.Lock()
	defer mu.Unlock()
	if existing, exists := catalog[t.Provider]; exists {
		if existing.DisplayName == t.DisplayName {
			return nil // idempotent re-registration of the same template
		}
		return errors.New("registry: duplicate provider slug: " + t.Provider)
	}
	// Validate actions if present.
	if len(t.Actions) > 0 {
		if err := template.ValidateActions(t.Actions); err != nil {
			return fmt.Errorf("registry: invalid actions for provider %q: %w", t.Provider, err)
		}
	}
	// Derive backward-compat fields from RuntimeSupport.
	t.RuntimeSupport.DefaultRuntime = t.RuntimeSupport.Preferred
	switch t.RuntimeSupport.DefaultRuntime { //nolint:staticcheck // QF1003: multi-value OR case retained for readability
	case RuntimeGatewayTyped, RuntimeGatewaySDK, RuntimeGatewayProxy:
		t.RuntimeSupport.GatewaySupported = true
		t.RuntimeSupport.RuntimeReason = "gateway mode selected"
	case RuntimeDirectBrokered:
		t.RuntimeSupport.GatewaySupported = false
		t.RuntimeSupport.RuntimeReason = "direct brokered mode selected"
	}
	catalog[t.Provider] = t
	return nil
}

// catalogGet looks up a provider by slug. Thread-safe.
func catalogGet(provider string) (ConnectionTemplate, error) {
	mu.RLock()
	defer mu.RUnlock()
	t, ok := catalog[provider]
	if !ok {
		return ConnectionTemplate{}, ErrProviderNotFound
	}
	return t, nil
}

// catalogList returns a sorted stable copy of all registered templates.
func catalogList() []ConnectionTemplate {
	mu.RLock()
	defer mu.RUnlock()
	list := make([]ConnectionTemplate, 0, len(catalog))
	for _, t := range catalog {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Provider < list[j].Provider
	})
	return list
}

// catalogListByCategory returns all templates with the given category.
func catalogListByCategory(cat string) []ConnectionTemplate {
	mu.RLock()
	defer mu.RUnlock()
	var out []ConnectionTemplate
	for _, t := range catalog {
		if t.Category == cat {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Provider < out[j].Provider
	})
	return out
}
