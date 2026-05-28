package registry_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFSLoader_MissingDir(t *testing.T) {
	loader := &registry.FSLoader{
		Dir:  "/nonexistent/path/that/does/not/exist",
		Tier: registry.TierLocal,
	}
	result, err := loader.LoadAll(context.Background())
	require.NoError(t, err, "missing directory should not return an error")
	assert.Nil(t, result, "missing directory should return nil slice")
}

func TestFSLoader_ValidTemplate(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(validMinimalTemplate), 0o600)
	require.NoError(t, err)

	loader := &registry.FSLoader{Dir: dir, Tier: registry.TierLocal}
	loaded, err := loader.LoadAll(context.Background())
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "test-provider", loaded[0].Template.Provider)
	assert.Equal(t, registry.SourceLocal, loaded[0].Source)
}

func TestFSLoader_SchemaInvalid(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(schemaInvalidTemplate), 0o600)
	require.NoError(t, err)

	loader := &registry.FSLoader{Dir: dir, Tier: registry.TierLocal}
	_, err = loader.LoadAll(context.Background())
	require.Error(t, err, "schema-invalid template must return an error")
}

func TestFSLoader_RequireSig_NoSigFile(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(validMinimalTemplate), 0o600)
	require.NoError(t, err)

	loader := &registry.FSLoader{Dir: dir, Tier: registry.TierCommunity, RequireSig: true}
	loaded, err := loader.LoadAll(context.Background())
	require.NoError(t, err, "missing .sig file should not return an error (template skipped)")
	assert.Empty(t, loaded, "template without .sig should be skipped")
}

func TestFSLoader_RequireSig_WithSigFile(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(validMinimalTemplate), 0o600)
	require.NoError(t, err)
	// Create a (dummy) sig file so the loader skips the sig-absent check.
	err = os.WriteFile(filepath.Join(dir, "test.yaml.sig"), []byte("dummy"), 0o600)
	require.NoError(t, err)

	loader := &registry.FSLoader{Dir: dir, Tier: registry.TierCommunity, RequireSig: true}
	loaded, err := loader.LoadAll(context.Background())
	require.NoError(t, err)
	require.Len(t, loaded, 1, "template with .sig file should be loaded")
	assert.Equal(t, registry.SourceCommunity, loaded[0].Source)
}
