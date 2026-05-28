// Package keeper implements the Keeper Commander backend for keylatch.
// register.go self-registers the keeper backend in backend.Default via init().
package keeper

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// KeeperConfig holds the typed configuration for the Keeper Commander backend.
type KeeperConfig struct {
	// Bin is the explicit path to the `keeper` binary. Optional.
	Bin string `mapstructure:"bin"`

	// AccountUID is the Keeper account UID for multi-account disambiguation. Optional.
	AccountUID string `mapstructure:"account_uid"`
}

func init() {
	if err := backend.Default.Register("keeper", keeperFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/keeper: %w", err))
	}
}

func keeperFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed KeeperConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("keeper backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("keeper backend: invalid settings: %w", err)
	}

	return Open(Options{
		Bin:        typed.Bin,
		AccountUID: typed.AccountUID,
		Runner:     kexec.DefaultRunner,
	})
}
