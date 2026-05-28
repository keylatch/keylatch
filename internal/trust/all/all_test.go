package all_test

import (
	"testing"

	_ "github.com/keylatch/keylatch/internal/trust/all"

	"github.com/keylatch/keylatch/internal/trust"
)

// TestTrustAvailableNonEmpty verifies that blank-importing trust/all registers
// at least one adapter, so trust.Available() returns a non-empty list.
func TestTrustAvailableNonEmpty(t *testing.T) {
	types := trust.Available()
	if len(types) == 0 {
		t.Fatal("trust.Available() returned empty slice; trust/all blank imports must register at least one adapter")
	}
}
