//go:build e2e

// Package e2e holds end-to-end tests that need real services.
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultwardenCollections writes an item through a namespace mapped to an
// organization collection and checks, with the bw CLI itself, that it landed in
// that collection under the organization. It runs against the Vaultwarden
// fixture in docker-compose.vaultwarden.yml and needs an organization that has
// the collection:
//
//	KEYLATCH_E2E_BW_SERVER      https URL of the fixture
//	KEYLATCH_E2E_BW_ORG         organization ID
//	KEYLATCH_E2E_BW_COLLECTION  collection name, for example Work/infra
//	BW_SESSION                  an unlocked session
func TestVaultwardenCollections(t *testing.T) {
	server, org, collection, session := os.Getenv("KEYLATCH_E2E_BW_SERVER"), os.Getenv("KEYLATCH_E2E_BW_ORG"),
		os.Getenv("KEYLATCH_E2E_BW_COLLECTION"), os.Getenv("BW_SESSION")
	if server == "" || org == "" || collection == "" || session == "" {
		t.Skip("set KEYLATCH_E2E_BW_SERVER, KEYLATCH_E2E_BW_ORG, KEYLATCH_E2E_BW_COLLECTION and BW_SESSION to run this test")
	}
	ctx := context.Background()

	b, err := bw.Open(bw.Options{
		Server:         server,
		OrganizationID: org,
		Namespaces:     map[string]string{"work": collection},
		Env: func(k string) string {
			if k == "BW_SESSION" {
				return session
			}
			return ""
		},
	})
	require.NoError(t, err)

	const path = "work/keylatch-e2e-collections/api_key"
	t.Cleanup(func() { _ = b.Delete(ctx, path) })
	require.NoError(t, b.Set(ctx, path, []byte("collections-e2e-value"), backend.Meta{Path: path}))

	got, _, err := b.Get(ctx, path)
	require.NoError(t, err)
	assert.Equal(t, "collections-e2e-value", string(got))

	out, err := exec.CommandContext(ctx, "bw", "list", "items", "--organizationid", org, "--search", "keylatch-e2e-collections").Output() //nolint:gosec // G204: fixed test arguments
	require.NoError(t, err)
	var items []struct {
		OrganizationID string   `json:"organizationId"`
		CollectionIDs  []string `json:"collectionIds"`
	}
	require.NoError(t, json.Unmarshal(out, &items))
	require.Len(t, items, 1)
	assert.Equal(t, org, items[0].OrganizationID)
	assert.NotEmpty(t, items[0].CollectionIDs)

	_, _, err = b.Get(ctx, "personal/keylatch-e2e-collections/api_key")
	assert.ErrorIs(t, err, bw.ErrNamespaceUnmapped, "an unmapped namespace is refused")
}
