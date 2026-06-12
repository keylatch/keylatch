package infisical

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

func TestInfisicalFactory_InvalidSettings(t *testing.T) {
	t.Parallel()
	// ErrorUnused: true — an unknown key must be rejected.
	_, err := infisicalFactory(context.Background(), backend.BackendConfig{
		Settings: map[string]any{"unknown_key": "x"},
	})
	if err == nil {
		t.Error("unknown settings key must fail decoding")
	}
}

func TestInfisicalFactory_ValidSettings(t *testing.T) {
	t.Parallel()
	b, err := infisicalFactory(context.Background(), backend.BackendConfig{
		Settings: map[string]any{
			"base_url":      "https://app.infisical.example",
			"client_id":     "cid",
			"client_secret": "cs",
			"workspace_id":  "ws",
			"environment":   "dev",
			"secret_path":   "/",
		},
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if b == nil || b.Name() != "infisical" {
		t.Errorf("factory returned %#v", b)
	}
}
