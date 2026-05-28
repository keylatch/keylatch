// Package doppler implements the Doppler backend for keylatch.
// init.go self-registers the doppler backend in backend.Default via init().
package doppler

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
)

// DopplerConfig holds the typed configuration for the Doppler backend.
type DopplerConfig struct {
	Token   string `mapstructure:"token"`
	Project string `mapstructure:"project"`
	Config  string `mapstructure:"config"`
	BaseURL string `mapstructure:"base_url"`
}

func init() {
	if err := backend.Default.Register("doppler", dopplerFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/doppler: %w", err))
	}
}

func dopplerFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed DopplerConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("doppler backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("doppler backend: invalid settings: %w", err)
	}

	return Open(Options{
		Token:   typed.Token,
		Project: typed.Project,
		Config:  typed.Config,
		BaseURL: typed.BaseURL,
	})
}
