//go:build e2e

// Package e2e holds end-to-end tests that need real services.
package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVaultwardenCollections writes an item through a namespace mapped to an
// organization collection and checks, with the bw CLI itself, that it landed in
// that collection under the disposable organization.
func TestVaultwardenCollections(t *testing.T) {
	f := newVaultwardenFixture(t)
	ctx := context.Background()
	b, runner := f.freshClient(t)

	const path = "work/keylatch-e2e-collections/api_key"
	t.Cleanup(func() { _ = b.Delete(ctx, path) })
	require.NoError(t, b.Set(ctx, path, []byte("collections-e2e-value"), backend.Meta{Path: path}))

	got, _, err := b.Get(ctx, path)
	require.NoError(t, err)
	assert.Equal(t, "collections-e2e-value", string(got))
	entries, err := b.List(ctx, "work/keylatch-e2e-collections/")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	out, _, code, err := runner.Run(ctx, f.bin, []string{"list", "items", "--organizationid", f.organization, "--search", "keylatch-e2e-collections"}, nil)
	require.NoError(t, err)
	require.Zero(t, code)
	var items []struct {
		OrganizationID string   `json:"organizationId"`
		CollectionIDs  []string `json:"collectionIds"`
	}
	require.NoError(t, json.Unmarshal(out, &items))
	require.Len(t, items, 1)
	assert.Equal(t, f.organization, items[0].OrganizationID)
	assert.NotEmpty(t, items[0].CollectionIDs)

	_, _, err = b.Get(ctx, "personal/keylatch-e2e-collections/api_key")
	assert.ErrorIs(t, err, bw.ErrNamespaceUnmapped, "an unmapped namespace is refused")
}
