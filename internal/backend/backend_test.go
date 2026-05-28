// Package backend_test contains basic error sentinel tests.
// The compliance test harness lives in internal/backendtest for reuse across
// concrete backend packages.
package backend_test

import (
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

func TestSentinelErrors(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrUnavailable", backend.ErrUnavailable},
		{"ErrNotFound", backend.ErrNotFound},
		{"ErrLocked", backend.ErrLocked},
		{"ErrACLMismatch", backend.ErrACLMismatch},
		{"ErrManifestCorrupt", backend.ErrManifestCorrupt},
	}

	for _, s := range sentinels {
		t.Run(s.name, func(t *testing.T) {
			if !errors.Is(s.err, s.err) {
				t.Errorf("errors.Is(%v, %v) == false", s.err, s.err)
			}
		})
	}
}
