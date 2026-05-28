// Package protonpass implements the Proton Pass backend for keylatch.
// register.go self-registers the proton-pass backend in backend.Default via init().
package protonpass

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// ProtonPassConfig holds the typed configuration for the Proton Pass backend.
type ProtonPassConfig struct {
	// Vault is the Proton Pass vault name. Optional.
	Vault string `mapstructure:"vault"`

	// Bin is the explicit path to the `pass-cli` binary. Optional.
	Bin string `mapstructure:"bin"`

	// ItemPrefix is a prefix applied to all item names. Defaults to "keylatch/".
	ItemPrefix string `mapstructure:"item_prefix"`
}

func init() {
	if err := backend.Default.Register("proton-pass", protonPassFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/protonpass: %w", err))
	}
}

func protonPassFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed ProtonPassConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("proton-pass backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("proton-pass backend: invalid settings: %w", err)
	}

	return Open(Options{
		Vault:      typed.Vault,
		Bin:        typed.Bin,
		ItemPrefix: typed.ItemPrefix,
		Runner:     kexec.DefaultRunner,
	})
}
