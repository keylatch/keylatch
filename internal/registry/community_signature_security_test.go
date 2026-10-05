//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
// Reuses the validMinimalTemplate fixture from embed_loader_test.go.
package registry_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

// KNOWN-FAILING: RequireSig only checks that a .sig file exists next
// to the template, not that its contents are a valid signature, so an
// arbitrary .sig file is accepted.
func TestSecurityRegression_CommunitySignature(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "test.yaml"), []byte(validMinimalTemplate), 0600)
	os.WriteFile(filepath.Join(d, "test.yaml.sig"), []byte("not-a-signature"), 0600)
	items, e := (&registry.FSLoader{Dir: d, Tier: registry.TierCommunity, RequireSig: true}).LoadAll(context.Background())
	if e == nil && len(items) > 0 {
		t.Fatal("RequireSig accepted template with arbitrary signature-file content")
	}
}
