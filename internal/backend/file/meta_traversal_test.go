package file_test

import (
	"context"
	"testing"

	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileBackend_MetaPathTraversalRejected verifies that GetMeta and SetMeta
// reject path-traversal inputs with the same "escapes vault root" guard used
// by Set/Delete. Metadata reads/writes go through
// metadataPath rather than FileBackend.Set/Delete, so this must be defended
// independently.
func TestFileBackend_MetaPathTraversalRejected(t *testing.T) {
	// Metadata files live one directory level deeper than value directories
	// (<root>/metadata/<canonical>.json vs <root>/<canonical>/value.enc), so
	// escaping the vault root here requires one extra "../" compared to the
	// equivalent Set/Delete traversal test in file_test.go.
	traversalPaths := []string{
		"../../escape",
		"../../../etc/passwd",
		"default/../../../escape",
	}

	t.Run("GetMeta", func(t *testing.T) {
		b := openKeyringBackend(t)
		defer b.Close()

		for _, p := range traversalPaths {
			p := p
			t.Run(p, func(t *testing.T) {
				_, err := b.GetMeta(context.Background(), p)
				require.Error(t, err, "GetMeta(%q): expected path-escape error, got nil", p)
				assert.Contains(t, err.Error(), "escapes vault root")
			})
		}
	})

	t.Run("SetMeta", func(t *testing.T) {
		b := openKeyringBackend(t)
		defer b.Close()

		for _, p := range traversalPaths {
			p := p
			t.Run(p, func(t *testing.T) {
				err := b.SetMeta(context.Background(), p, vmeta.Meta{Path: p})
				require.Error(t, err, "SetMeta(%q): expected path-escape error, got nil", p)
				assert.Contains(t, err.Error(), "escapes vault root")
			})
		}
	})
}
