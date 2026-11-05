//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
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
// returns the importer and an independent client factory for restore verification.
func drillFixture(t *testing.T) (bwStore, func() bwStore, migrate.Manifest, []byte, []string) {
	t.Helper()
	f := newVaultwardenFixture(t)
	b, _ := f.freshClient(t)
	fresh := func() bwStore { client, _ := f.freshClient(t); return bwStore{client} }

	dir := t.TempDir()
	env := filepath.Join(dir, "drill.env")
	require.NoError(t, os.WriteFile(env, []byte("DRILL_ONE=value-one\nDRILL_TWO=value-two\nDRILL_THREE=value-three\n"), 0o600))
	plan := migrate.Plan{Version: 1}
	var paths []string
	for _, k := range []string{"DRILL_ONE", "DRILL_TWO", "DRILL_THREE"} {
		p := "work/keylatch-e2e-drill-" + strings.ToLower(k) + "/value"
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
	data, err := json.Marshal(res.Manifest)
	require.NoError(t, err)
	manifest, err := migrate.ParseManifest(data)
	require.NoError(t, err)
	clear(key)
	key, err = manifest.KDF.Key([]byte("drill recovery passphrase"))
	require.NoError(t, err)
	t.Cleanup(func() { clear(key) })
	return store, fresh, manifest, key, paths
}

// A separately authenticated client restores from the serialized manifest.
func TestRestoreDrillClean(t *testing.T) {
	_, fresh, manifest, key, _ := drillFixture(t)
	rep, err := migrate.Verify(context.Background(), manifest, key, fresh(), nil)
	require.NoError(t, err)
	assert.Equal(t, len(manifest.Items), rep.OK)
	assert.Empty(t, rep.Failed)
	assert.Empty(t, rep.Missing)
}

// An item removed from the backend is reported as missing.
func TestRestoreDrillMissingItem(t *testing.T) {
	store, fresh, manifest, key, paths := drillFixture(t)
	require.NoError(t, store.b.Delete(context.Background(), paths[1]))
	rep, err := migrate.Verify(context.Background(), manifest, key, fresh(), nil)
	require.NoError(t, err)
	assert.Equal(t, len(manifest.Items)-1, rep.OK)
	assert.Equal(t, []string{paths[1]}, rep.Missing)
}

func TestRestoreDrillChangedItem(t *testing.T) {
	store, fresh, manifest, key, paths := drillFixture(t)
	require.NoError(t, store.Put(context.Background(), paths[1], []byte("changed-after-import")))
	rep, err := migrate.Verify(context.Background(), manifest, key, fresh(), nil)
	require.NoError(t, err)
	assert.Equal(t, len(manifest.Items)-1, rep.OK)
	assert.Equal(t, []string{paths[1]}, rep.Failed)
	assert.Empty(t, rep.Missing)
}
