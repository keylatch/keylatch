package azurekv

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

func TestAzureKVFactory_Errors(t *testing.T) {
	t.Parallel()
	// Unknown settings key rejected (ErrorUnused).
	if _, err := azureKVFactory(context.Background(), backend.BackendConfig{
		Settings: map[string]any{"bogus": "x"},
	}); err == nil {
		t.Error("unknown settings key must fail")
	}
	// Missing vault_url rejected by Open.
	if _, err := azureKVFactory(context.Background(), backend.BackendConfig{
		Settings: map[string]any{},
	}); err == nil {
		t.Error("missing vault_url must fail")
	}
}

func TestOpen_MissingVaultURL(t *testing.T) {
	t.Parallel()
	if _, err := Open(Options{}); err == nil {
		t.Error("Open without VaultURL must fail")
	}
}
