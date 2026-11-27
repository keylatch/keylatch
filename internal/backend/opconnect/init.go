// Package opconnect implements the 1Password Connect backend for keylatch.
// init.go self-registers the op-connect backend in backend.Default via init().
package opconnect

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
)

// OPConnectConfig holds the typed configuration for the 1Password Connect backend.
type OPConnectConfig struct {
	ConnectURL string `mapstructure:"connect_url"` // e.g. http://localhost:8080
	Token      string `mapstructure:"token"`       // service-account token
	VaultID    string `mapstructure:"vault_id"`    // OP vault UUID
}

func init() {
	if err := backend.Default.Register("op-connect", opConnectFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/opconnect: %w", err))
	}
}

func opConnectFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed OPConnectConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("op-connect backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("op-connect backend: invalid settings: %w", err)
	}

	return Open(Options{
		ConnectURL: typed.ConnectURL,
		Token:      typed.Token,
		VaultID:    typed.VaultID,
	})
}
