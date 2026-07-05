package vault

import (
	"github.com/keylatch/keylatch/internal/registry"
	vpath "github.com/keylatch/keylatch/internal/vault/path"
)

// resolveCategory looks up the category for a provider slug via the
// registry. Returns vpath.ErrUnknownProvider if the provider is not registered.
func resolveCategory(provider string) (string, error) {
	tmpl, err := registry.Get(provider)
	if err != nil {
		return "", vpath.ErrUnknownProvider
	}
	return tmpl.Category, nil
}
