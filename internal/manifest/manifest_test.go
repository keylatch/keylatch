package manifest_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrent_Loadable(t *testing.T) {
	m := manifest.Current()
	require.NotEmpty(t, m.Entries)
}

func TestCurrent_NoDuplicateIDs(t *testing.T) {
	m := manifest.Current()
	seen := make(map[string]bool, len(m.Entries))
	for _, e := range m.Entries {
		require.False(t, seen[e.ID], "duplicate manifest entry ID %q", e.ID)
		seen[e.ID] = true
	}
}

func TestCurrent_EveryEntryHasValidFields(t *testing.T) {
	m := manifest.Current()
	for _, e := range m.Entries {
		assert.NotEmpty(t, e.ID)
		assert.NotEmpty(t, e.Note, "entry %q must document its disposition", e.ID)
		switch e.Status {
		case manifest.Supported, manifest.Preview, manifest.Community, manifest.Deprecated, manifest.Unavailable, manifest.Experimental:
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

// TestCurrent_BackendTiers encodes the backend support policy table.
func TestCurrent_BackendTiers(t *testing.T) {
	m := manifest.Current()
	tiers := map[manifest.Status][]string{
		manifest.Supported:   {"bw", "op"},
		manifest.Unavailable: {"file"},
		manifest.Community:   {"vault", "aws-sm", "gcp-sm", "azure-kv", "doppler", "infisical", "op-connect", "bws", "sops"},
		manifest.Deprecated:  {"keychain", "keeper", "lastpass", "proton-pass"},
	}
	total := 0
	for status, ids := range tiers {
		for _, id := range ids {
			assert.Equal(t, status, m.Status(id), "backend %q", id)
			total++
		}
	}
	assert.Len(t, m.ByCategory(manifest.CategoryManager), total, "every manager entry must appear in the policy table")
}

// TestCurrent_OnlySupportedAndPreviewAreEnabled proves community and
// deprecated backends are listed but never enabled by the manifest.
func TestCurrent_OnlySupportedAndPreviewAreEnabled(t *testing.T) {
	m := manifest.Current()
	for _, id := range []string{"op", "bw", "linux", "macos", "windows"} {
		assert.True(t, m.Enabled(id), "%q must be enabled", id)
	}
	for _, id := range []string{"file", "op-connect", "keeper", "proton-pass", "lastpass", "keychain", "vault"} {
		assert.False(t, m.Enabled(id), "backend %q must not be enabled", id)
	}
	assert.Equal(t, manifest.Preview, m.Status("macos"))
	assert.Equal(t, manifest.Preview, m.Status("windows"))
}

// TestCurrent_FileBackendIsNotEnabled: the file backend is not a manager, so
// it opens only through the explicit opt-in.
func TestCurrent_FileBackendIsNotEnabled(t *testing.T) {
	m := manifest.Current()
	assert.Equal(t, manifest.Unavailable, m.Status("file"))
	assert.False(t, m.Enabled("file"))
}

// TestCurrent_RuntimeCohort locks in the excluded runtimes: gateway_proxy
// stays unreachable, with no fallback into a direct secret-injection mode.
// The classic sandboxed runtime no longer exists, and direct_brokered is
// minted.
func TestCurrent_RuntimeCohort(t *testing.T) {
	m := manifest.Current()
	assert.True(t, m.Enabled("gateway_typed"))
	assert.True(t, m.Enabled("gateway_sdk"))

	assert.True(t, m.Enabled("minted"))
	for _, id := range []string{"gateway_proxy", "direct_brokered"} {
		assert.False(t, m.Enabled(id), "runtime %q must not be enabled", id)
	}
	_, tracked := m.Lookup("direct_classic_sandboxed")
	assert.False(t, tracked, "direct_classic_sandboxed was removed")
}

// TestCurrent_ExcludedFeatures locks in every explicitly excluded feature.
func TestCurrent_ExcludedFeatures(t *testing.T) {
	m := manifest.Current()
	excluded := []string{
		"admin", "team", "sso", "hardware_attestation", "approval_inbox",
		"hosted_telemetry", "receipt_sharing", "community_loading",
		"tauri_desktop", "manager_mutation",
	}
	for _, id := range excluded {
		assert.False(t, m.Enabled(id), "feature %q must not be enabled", id)
	}
}

// TestUnknownID_DefaultsUnavailable proves the default-deny fallback: an ID
// the manifest has never heard of is never treated as usable.
func TestUnknownID_DefaultsUnavailable(t *testing.T) {
	m := manifest.Current()
	assert.False(t, m.Enabled("some-future-manager-nobody-added-yet"))
	assert.Equal(t, manifest.Unavailable, m.Status("some-future-manager-nobody-added-yet"))
}

// TestExperimental_NeverEnabled proves structurally — not just by current
// data — that Enabled() can never return true for an Experimental entry,
// regardless of what future entries are added to the table.
func TestExperimental_NeverEnabled(t *testing.T) {
	synthetic := manifest.Manifest{
		Entries: []manifest.Entry{
			{ID: "future-credential-path", Category: manifest.CategoryManager, Status: manifest.Experimental, Note: "not yet certified"},
		},
	}
	assert.False(t, synthetic.Enabled("future-credential-path"))
	assert.Equal(t, manifest.Experimental, synthetic.Status("future-credential-path"))
}

func TestByCategory(t *testing.T) {
	m := manifest.Current()
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

// knownFailingBackends have a KNOWN-FAILING security test (op-connect: the
// duplicate-creating upsert; keeper and proton-pass: the shared cache slice)
// or are platform-gated (keychain); none may be opened by any opt-in.
var knownFailingBackends = []string{"op-connect", "keeper", "proton-pass", "keychain"}

func TestCurrent_NoKnownFailingBackendCanBeOptedInto(t *testing.T) {
	m := manifest.Current()
	for _, id := range knownFailingBackends {
		e, ok := m.Lookup(id)
		require.True(t, ok, id)
		assert.False(t, e.OptIn, "%s must not carry the opt-in marker", id)
		assert.False(t, m.OptInAllowed(id), id)
	}
	for _, e := range m.Entries {
		if e.OptIn {
			assert.Equal(t, manifest.CategoryManager, e.Category, "%s: only managers take the marker", e.ID)
			assert.False(t, m.Enabled(e.ID), "%s: an enabled entry needs no marker", e.ID)
		}
	}
	assert.True(t, m.OptInAllowed("file"))
}
