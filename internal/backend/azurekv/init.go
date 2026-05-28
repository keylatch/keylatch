// Package azurekv implements the Azure Key Vault backend for keylatch.
// init.go self-registers the azure-kv backend in backend.Default via init().
package azurekv

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
)

// AzureConfig holds the typed configuration for the Azure Key Vault backend.
type AzureConfig struct {
	VaultURL     string `mapstructure:"vault_url"`
	TenantID     string `mapstructure:"tenant_id"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

func init() {
	if err := backend.Default.Register("azure-kv", azureKVFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/azurekv: %w", err))
	}
}

func azureKVFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed AzureConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("azure-kv backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("azure-kv backend: invalid settings: %w", err)
	}

	return Open(Options{
		VaultURL:     typed.VaultURL,
		TenantID:     typed.TenantID,
		ClientID:     typed.ClientID,
		ClientSecret: typed.ClientSecret,
	})
}
