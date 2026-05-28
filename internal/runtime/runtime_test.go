package runtime_test

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
)

func TestAllModesCount(t *testing.T) {
	// EPIC-24: direct_classic_sandboxed reinstated as a new sibling mode.
	// direct_classic remains permanently removed.
	// Five modes: gateway_typed, gateway_sdk, direct_brokered, gateway_proxy,
	// direct_classic_sandboxed.
	assert.Len(t, runtime.AllModes, 5, "AllModes must contain exactly 5 runtime modes after EPIC-24")
}

func TestAllModesUnique(t *testing.T) {
	seen := map[runtime.RuntimeMode]bool{}
	for _, m := range runtime.AllModes {
		assert.False(t, seen[m], "duplicate mode %q in AllModes", m)
		seen[m] = true
	}
}

func TestNoUnrestrictedMode(t *testing.T) {
	for _, m := range runtime.AllModes {
		assert.False(t,
			strings.Contains(string(m), "unrestricted"),
			"AllModes must not contain any unrestricted mode; found %q", m)
	}
}
