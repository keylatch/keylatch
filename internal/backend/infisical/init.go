// Package infisical implements the Infisical backend for keylatch.
// init.go self-registers the infisical backend in backend.Default via init().
package infisical

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
)

// InfisicalConfig holds the typed configuration for the Infisical backend.
type InfisicalConfig struct {
	BaseURL      string `mapstructure:"base_url"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	WorkspaceID  string `mapstructure:"workspace_id"`
	Environment  string `mapstructure:"environment"`
	SecretPath   string `mapstructure:"secret_path"`
}

func init() {
	if err := backend.Default.Register("infisical", infisicalFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/infisical: %w", err))
	}
}

func infisicalFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed InfisicalConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("infisical backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("infisical backend: invalid settings: %w", err)
	}

	return Open(Options{
		BaseURL:      typed.BaseURL,
		ClientID:     typed.ClientID,
		ClientSecret: typed.ClientSecret,
		WorkspaceID:  typed.WorkspaceID,
		Environment:  typed.Environment,
		SecretPath:   typed.SecretPath,
	})
}
