package op_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/op" // trigger init()
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
