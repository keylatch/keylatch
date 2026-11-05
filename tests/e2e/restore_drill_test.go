//go:build e2e

package e2e

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/migrate"
)

type bwStore struct{ b backend.Backend }

func (s bwStore) Get(ctx context.Context, p string) ([]byte, error) {
	v, _, err := s.b.Get(ctx, p)
	if errors.Is(err, backend.ErrNotFound) {
		return nil, migrate.ErrNotFound
	}
	return v, err
}

func (s bwStore) Put(ctx context.Context, p string, v []byte) error {
	return s.b.Set(ctx, p, v, backend.Meta{Path: p})
}

// drillFixture imports three env-file items into the Vaultwarden fixture and
// returns the store, the manifest and the key. It needs the same variables as
// TestVaultwardenCollections.
func drillFixture(t *testing.T) (bwStore, migrate.Manifest, []byte, []string) {
	t.Helper()
	server, org, collection, session := os.Getenv("KEYLATCH_E2E_BW_SERVER"), os.Getenv("KEYLATCH_E2E_BW_ORG"),
		os.Getenv("KEYLATCH_E2E_BW_COLLECTION"), os.Getenv("BW_SESSION")
	if server == "" || org == "" || collection == "" || session == "" {
		t.Skip("set KEYLATCH_E2E_BW_SERVER, KEYLATCH_E2E_BW_ORG, KEYLATCH_E2E_BW_COLLECTION and BW_SESSION to run this test")
	}
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

	dir := t.TempDir()
	env := filepath.Join(dir, "drill.env")
	require.NoError(t, os.WriteFile(env, []byte("DRILL_ONE=value-one\nDRILL_TWO=value-two\nDRILL_THREE=value-three\n"), 0o600))
	plan := migrate.Plan{Version: 1}
	var paths []string
	for _, k := range []string{"DRILL_ONE", "DRILL_TWO", "DRILL_THREE"} {
		p := "work/keylatch-e2e-drill/" + k
		paths = append(paths, p)
		plan.Items = append(plan.Items, migrate.PlanItem{Name: k, Source: "env-file", Ref: "env:" + env + "#" + k, Namespace: "work", Path: p})
	}
	t.Cleanup(func() {
		for _, p := range paths {
			_ = b.Delete(context.Background(), p)
		}
	})

	kdf, err := migrate.NewKDF()
	require.NoError(t, err)
	key, err := kdf.Key([]byte("drill recovery passphrase"))
	require.NoError(t, err)
	store := bwStore{b}
	res := migrate.Import(context.Background(), plan, migrate.Env{}, store, migrate.ImportOptions{Key: key, KDF: kdf})
	require.Zero(t, res.Failed)
	require.NotNil(t, res.Manifest)
	return store, *res.Manifest, key, paths
}

// A drill on a clean HOME, with only the backend configured, restores every item.
func TestRestoreDrillClean(t *testing.T) {
	store, manifest, key, _ := drillFixture(t)
	t.Setenv("HOME", t.TempDir())
	rep, err := migrate.Verify(context.Background(), manifest, key, store, nil)
	require.NoError(t, err)
	assert.Equal(t, len(manifest.Items), rep.OK)
	assert.Empty(t, rep.Failed)
	assert.Empty(t, rep.Missing)
}

// An item removed from the backend is reported as missing.
func TestRestoreDrillMissingItem(t *testing.T) {
	store, manifest, key, paths := drillFixture(t)
	require.NoError(t, store.b.Delete(context.Background(), paths[1]))
	rep, err := migrate.Verify(context.Background(), manifest, key, store, nil)
	require.NoError(t, err)
	assert.Equal(t, len(manifest.Items)-1, rep.OK)
	assert.Equal(t, []string{paths[1]}, rep.Missing)
}
