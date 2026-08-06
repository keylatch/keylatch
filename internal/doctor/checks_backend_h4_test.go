package doctor_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDoctor_BackendSelected_AllKnownCanonicalNamesPass is the H4 regression
// test: checkBackendSelected must accept every backend in
// backend.KnownCanonicalNames() (derived from the same catalog the registry
// uses), not just the stale 7-entry literal list that hard-FAILed vault,
// aws-sm, gcp-sm, azure-kv, doppler, infisical, and op-connect.
func TestDoctor_BackendSelected_AllKnownCanonicalNamesPass(t *testing.T) {
	for _, name := range backend.KnownCanonicalNames() {
		name := name
		t.Run(name, func(t *testing.T) {
			_, env := bootstrappedHome(t)
			if name != "keychain" {
				// keychain is macOS-only by design — exercised separately;
				// every other canonical name must pass on any platform.
				selectBackend(t, env, name)
			}

			report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: newMockProbe()})
			require.NoError(t, err)

			s := findCheck(t, report, "backend.selected")
			if name == "keychain" {
				return // covered by the darwin-only assumption elsewhere.
			}
			assert.True(t, s.OK, "backend=%s: expected OK=true, got Detail=%q Fix=%q", name, s.Detail, s.Fix)
		})
	}
}

// TestDoctor_BackendSelected_UnknownValueFails verifies the FAIL path still
// works for a genuinely unrecognised backend value.
func TestDoctor_BackendSelected_UnknownValueFails(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "not-a-real-backend")

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: newMockProbe()})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.selected")
	assert.False(t, s.OK)
	assert.Contains(t, s.Detail, "not-a-real-backend")
}

// TestDoctor_BackendSelected_AliasesNormalize verifies that alias names
// (e.g. "hashivault" -> "vault") resolve through backend.CanonicalName
// rather than failing because the alias itself isn't a canonical name.
func TestDoctor_BackendSelected_AliasesNormalize(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "hashivault")

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: newMockProbe()})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.selected")
	assert.True(t, s.OK, "alias 'hashivault' should normalize to canonical 'vault'")
	assert.Contains(t, s.Detail, "vault")
}
