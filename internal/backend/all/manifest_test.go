package all_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/all"
	"github.com/keylatch/keylatch/internal/manifest"
)

// A backend with no manifest entry would read as Unavailable by default, but
// an entry must say why; every registered ID and every catalog name needs one.
func TestEveryRegisteredBackendHasAManifestEntry(t *testing.T) {
	m := manifest.Current()
	registered := backend.Default.List()
	if len(registered) == 0 {
		t.Fatal("no backends registered")
	}
	for _, id := range registered {
		e, ok := m.Lookup(id)
		if !ok {
			t.Errorf("registered backend %q has no manifest entry", id)
			continue
		}
		if e.Category != manifest.CategoryManager {
			t.Errorf("manifest entry %q is a %s, want a manager", id, e.Category)
		}
	}
	for _, id := range backend.KnownCanonicalNames() {
		if _, ok := m.Lookup(id); !ok {
			t.Errorf("catalog name %q has no manifest entry", id)
		}
	}
}
