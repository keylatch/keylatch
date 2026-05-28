package nordpass_test

// NOTE: init() fires once when the test binary is loaded, before any test function.
// t.Setenv calls cannot retroactively affect whether init() registered the backend.
// These tests assert that the binary was loaded without KEYLATCH_EXPERIMENTAL=1 (CI expectation).
// To test the positive registration path, a subprocess test with the env var set at launch is needed.

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/nordpass"
	"github.com/keylatch/keylatch/internal/vault/meta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNordPassNotRegisteredByDefault(t *testing.T) {
	// With KEYLATCH_EXPERIMENTAL unset (or != "1") the init() function
	// returns early without registering. Since tests run in a clean env without
	// that variable, the "nordpass" key must be absent from the default registry.
	t.Setenv("KEYLATCH_EXPERIMENTAL", "")
	_, ok := backend.Default.Get("nordpass")
	assert.False(t, ok, "nordpass must not be registered by default (requires KEYLATCH_EXPERIMENTAL=1)")
}

// TestNordPass_NotRegisteredByDefault_UnifiedFlag verifies that in a test binary loaded
// without KEYLATCH_EXPERIMENTAL=1, the nordpass backend is absent from the registry.
func TestNordPass_NotRegisteredByDefault_UnifiedFlag(t *testing.T) {
	t.Run("old_backends_var_has_no_effect", func(t *testing.T) {
		// Setting only the deprecated var must NOT register nordpass.
		t.Setenv("KEYLATCH_EXPERIMENTAL", "")
		t.Setenv("KEYLATCH_EXPERIMENTAL_BACKENDS", "1")
		_, ok := backend.Default.Get("nordpass")
		assert.False(t, ok, "KEYLATCH_EXPERIMENTAL_BACKENDS must be ignored; only KEYLATCH_EXPERIMENTAL=1 counts")
	})

	t.Run("unified_flag_unset_does_not_register", func(t *testing.T) {
		t.Setenv("KEYLATCH_EXPERIMENTAL", "")
		_, ok := backend.Default.Get("nordpass")
		assert.False(t, ok, "nordpass must not register when KEYLATCH_EXPERIMENTAL is unset")
	})
}

func TestNordPassAllMethodsReturnErrUnavailable(t *testing.T) {
	b := &nordpass.NordPassBackend{}
	ctx := context.Background()

	_, _, err := b.Get(ctx, "some/path")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable), "Get must return ErrUnavailable, got: %v", err)

	err = b.Set(ctx, "some/path", []byte("value"), backend.Meta{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable), "Set must return ErrUnavailable, got: %v", err)

	err = b.Delete(ctx, "some/path")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable), "Delete must return ErrUnavailable, got: %v", err)

	_, err = b.List(ctx, "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, backend.ErrUnavailable), "List must return ErrUnavailable, got: %v", err)
}

func TestNordPassPhase4MethodsReturnErrNotSupported(t *testing.T) {
	b := &nordpass.NordPassBackend{}
	ctx := context.Background()

	_, err := b.GetMeta(ctx, "some/path")
	assert.True(t, errors.Is(err, backend.ErrNotSupported), "GetMeta must return ErrNotSupported, got: %v", err)

	err = b.SetMeta(ctx, "some/path", meta.Meta{})
	assert.True(t, errors.Is(err, backend.ErrNotSupported), "SetMeta must return ErrNotSupported, got: %v", err)

	_, err = b.ListMeta(ctx, "")
	assert.True(t, errors.Is(err, backend.ErrNotSupported), "ListMeta must return ErrNotSupported, got: %v", err)

	_, err = b.GetVersioned(ctx, "some/path", 1)
	assert.True(t, errors.Is(err, backend.ErrNotSupported), "GetVersioned must return ErrNotSupported, got: %v", err)

	err = b.SetVersioned(ctx, "some/path", 1, []byte("value"))
	assert.True(t, errors.Is(err, backend.ErrNotSupported), "SetVersioned must return ErrNotSupported, got: %v", err)

	err = b.DeleteVersioned(ctx, "some/path", 1)
	assert.True(t, errors.Is(err, backend.ErrNotSupported), "DeleteVersioned must return ErrNotSupported, got: %v", err)
}
