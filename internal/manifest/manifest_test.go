package manifest_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestM1_Loadable(t *testing.T) {
	m := manifest.M1()
	require.Equal(t, "M1", m.Milestone)
	require.NotEmpty(t, m.Entries)
}

func TestM1_NoDuplicateIDs(t *testing.T) {
	m := manifest.M1()
	seen := make(map[string]bool, len(m.Entries))
	for _, e := range m.Entries {
		require.False(t, seen[e.ID], "duplicate manifest entry ID %q", e.ID)
		seen[e.ID] = true
	}
}

func TestM1_EveryEntryHasValidFields(t *testing.T) {
	m := manifest.M1()
	for _, e := range m.Entries {
		assert.NotEmpty(t, e.ID)
		assert.NotEmpty(t, e.Note, "entry %q must document its disposition", e.ID)
		switch e.Status {
		case manifest.Supported, manifest.Unavailable, manifest.Experimental:
		default:
			t.Errorf("entry %q has unknown status %q", e.ID, e.Status)
		}
		switch e.Category {
		case manifest.CategoryManager, manifest.CategoryRuntime, manifest.CategoryFeature, manifest.CategoryPlatform:
		default:
			t.Errorf("entry %q has unknown category %q", e.ID, e.Category)
		}
	}
}

// TestM1_ManagerCohort locks in the two-manager M1 cohort — the plan's
// mandatory concurrent-manager requirement depends on exactly these two
// being enabled.
func TestM1_ManagerCohort(t *testing.T) {
	m := manifest.M1()
	assert.True(t, m.Enabled("op"))
	assert.True(t, m.Enabled("bw"))

	for _, id := range []string{"vaultwarden", "opconnect", "keeper", "proton-pass", "lastpass", "keychain", "file"} {
		assert.False(t, m.Enabled(id), "manager %q must not be enabled in M1", id)
		assert.Equal(t, manifest.Unavailable, m.Status(id))
	}
}

// TestM1_RuntimeCohort locks in the M1 explicit-exclusions list from the
// plan: gateway_proxy, direct_brokered, and direct_classic_sandboxed must
// stay unreachable, with no fallback into a direct secret-injection mode.
func TestM1_RuntimeCohort(t *testing.T) {
	m := manifest.M1()
	assert.True(t, m.Enabled("gateway_typed"))
	assert.True(t, m.Enabled("gateway_sdk"))

	for _, id := range []string{"gateway_proxy", "direct_brokered", "direct_classic_sandboxed"} {
		assert.False(t, m.Enabled(id), "runtime %q must not be enabled in M1", id)
	}
}

// TestM1_ExcludedFeatures locks in every feature named in the plan's
// "Explicit exclusions" subsection.
func TestM1_ExcludedFeatures(t *testing.T) {
	m := manifest.M1()
	excluded := []string{
		"admin", "team", "sso", "hardware_attestation", "approval_inbox",
		"hosted_telemetry", "receipt_sharing", "community_loading",
		"tauri_desktop", "manager_mutation",
	}
	for _, id := range excluded {
		assert.False(t, m.Enabled(id), "feature %q must not be enabled in M1", id)
	}
}

// TestUnknownID_DefaultsUnavailable proves the default-deny fallback: an ID
// the manifest has never heard of is never treated as usable.
func TestUnknownID_DefaultsUnavailable(t *testing.T) {
	m := manifest.M1()
	assert.False(t, m.Enabled("some-future-manager-nobody-added-yet"))
	assert.Equal(t, manifest.Unavailable, m.Status("some-future-manager-nobody-added-yet"))
}

// TestExperimental_NeverEnabled proves structurally — not just by current
// M1 data — that Enabled() can never return true for an Experimental entry,
// regardless of what future entries are added to the table.
func TestExperimental_NeverEnabled(t *testing.T) {
	synthetic := manifest.Manifest{
		Milestone: "test",
		Entries: []manifest.Entry{
			{ID: "future-credential-path", Category: manifest.CategoryManager, Status: manifest.Experimental, Note: "not yet certified"},
		},
	}
	assert.False(t, synthetic.Enabled("future-credential-path"))
	assert.Equal(t, manifest.Experimental, synthetic.Status("future-credential-path"))
}

func TestByCategory(t *testing.T) {
	m := manifest.M1()
	managers := m.ByCategory(manifest.CategoryManager)
	require.NotEmpty(t, managers)
	for _, e := range managers {
		assert.Equal(t, manifest.CategoryManager, e.Category)
	}
}

func TestEntryString(t *testing.T) {
	e := manifest.Entry{ID: "op", Category: manifest.CategoryManager, Status: manifest.Supported, Note: "example"}
	assert.Equal(t, "op: supported (example)", e.String())
}
