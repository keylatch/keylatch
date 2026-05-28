// Package gcpsm implements the GCP Secret Manager backend for keylatch.
// init.go self-registers the gcp-sm backend in backend.Default via init().
package gcpsm

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
)

// GCPConfig holds the typed configuration for the GCP Secret Manager backend.
type GCPConfig struct {
	ProjectID   string `mapstructure:"project_id"`
	Credentials string `mapstructure:"credentials_json"` // path to SA JSON; empty = ADC
}

func init() {
	if err := backend.Default.Register("gcp-sm", gcpSMFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/gcpsm: %w", err))
	}
}

func gcpSMFactory(ctx context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed GCPConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp-sm backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("gcp-sm backend: invalid settings: %w", err)
	}

	return Open(ctx, Options{
		ProjectID:       typed.ProjectID,
		CredentialsFile: typed.Credentials,
	})
}
