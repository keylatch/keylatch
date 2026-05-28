package sandbox_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/sandbox"
)

// TestLoadManifest_TraversalRejected verifies that LoadManifest rejects profile
// IDs that contain path separators or are relative traversal references (C3).
func TestLoadManifest_TraversalRejected(t *testing.T) {
	traversalInputs := []string{
		"../../etc/passwd",
		"../secret",
		"..\\windows\\system32",
		"foo/bar",
		"foo\\bar",
		"..",
		".",
		"",
	}

	for _, id := range traversalInputs {
		t.Run("id="+id, func(t *testing.T) {
			_, err := sandbox.LoadManifest(id)
			if err == nil {
				t.Errorf("LoadManifest(%q) should have returned an error for path traversal input", id)
			}
		})
	}
}
