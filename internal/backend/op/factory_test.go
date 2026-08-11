package op_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/op" // trigger init()
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOPFactory_UnknownKey_ReturnsError(t *testing.T) {
	factory, ok := backend.Default.Get("op")
	if !ok {
		t.Fatal("op backend not registered; import side-effect missing")
	}

	cfg := backend.BackendConfig{
		Name: "op",
		Settings: map[string]interface{}{
			"vault":       "Keylatch",
			"unknown_key": "should-cause-error",
		},
	}

	_, err := factory(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unknown settings key, got nil")
	}
}

// TestOPFactory_NoEnvKey_UsesDefaultLookup covers opFactory's fallback path
// when cfg.Settings has no "env" key at all — envFn stays nil and Open()
// substitutes llmcontext.DefaultLookup. Bin is set explicitly so Open()
// never touches the real PATH.
func TestOPFactory_NoEnvKey_UsesDefaultLookup(t *testing.T) {
	factory, ok := backend.Default.Get("op")
	require.True(t, ok, "op backend not registered; import side-effect missing")

	cfg := backend.BackendConfig{
		Name: "op",
		Settings: map[string]interface{}{
			"vault": "Keylatch",
			"bin":   fakeOpBin,
		},
	}

	b, err := factory(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "op", b.Name())
}

// TestOPFactory_EnvAsRawFunc covers the "func(string) string" branch of
// opFactory's type switch on cfg.Settings["env"]. StripNonStringSettings
// drops non-string values (including funcs) before the mapstructure decode,
// so this key never trips the decoder's ErrorUnused check.
func TestOPFactory_EnvAsRawFunc(t *testing.T) {
	factory, ok := backend.Default.Get("op")
	require.True(t, ok, "op backend not registered; import side-effect missing")

	var rawFn func(string) string = func(string) string { return "" }
	cfg := backend.BackendConfig{
		Name: "op",
		Settings: map[string]interface{}{
			"vault": "Keylatch",
			"bin":   fakeOpBin,
			"env":   rawFn,
		},
	}

	b, err := factory(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, b)
}

// TestOPFactory_EnvAsLLMContextLookup covers the llmcontext.Lookup branch of
// opFactory's type switch — distinct dynamic type from a bare func(string)string.
func TestOPFactory_EnvAsLLMContextLookup(t *testing.T) {
	factory, ok := backend.Default.Get("op")
	require.True(t, ok, "op backend not registered; import side-effect missing")

	var lk llmcontext.Lookup = func(string) string { return "" }
	cfg := backend.BackendConfig{
		Name: "op",
		Settings: map[string]interface{}{
			"vault": "Keylatch",
			"bin":   fakeOpBin,
			"env":   lk,
		},
	}

	b, err := factory(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, b)
}

// TestOPFactory_EnvWrongType covers the case where "env" is present but
// matches neither type-switch branch — envFn stays nil and Open() falls
// back to llmcontext.DefaultLookup, same as when no "env" key is set at
// all. A non-string, non-nil value (int) is required here so
// StripNonStringSettings drops it before the mapstructure decode.
func TestOPFactory_EnvWrongType(t *testing.T) {
	factory, ok := backend.Default.Get("op")
	require.True(t, ok, "op backend not registered; import side-effect missing")

	cfg := backend.BackendConfig{
		Name: "op",
		Settings: map[string]interface{}{
			"vault": "Keylatch",
			"bin":   fakeOpBin,
			"env":   42,
		},
	}

	b, err := factory(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, b)
}
