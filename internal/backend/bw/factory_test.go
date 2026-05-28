package bw_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/bw" // trigger init()
)

func TestBWFactory_UnknownKey_ReturnsError(t *testing.T) {
	factory, ok := backend.Default.Get("bw")
	if !ok {
		t.Fatal("bw backend not registered; import side-effect missing")
	}

	cfg := backend.BackendConfig{
		Name: "bw",
		Settings: map[string]interface{}{
			"server":      "",
			"unknown_key": "should-cause-error",
		},
	}

	_, err := factory(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unknown settings key, got nil")
	}
}
