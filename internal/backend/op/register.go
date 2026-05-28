// Package op implements the 1Password backend for keylatch.
// register.go self-registers the op backend in backend.Default via init().
package op

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// OPConfig holds the typed configuration for the 1Password backend.
type OPConfig struct {
	// Vault is the 1Password vault name. Defaults to "Keylatch".
	Vault string `mapstructure:"vault"`

	// Bin is the explicit path to the `op` binary. Optional.
	Bin string `mapstructure:"bin"`
}

func init() {
	if err := backend.Default.Register("op", opFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/op: %w", err))
	}
}

func opFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	// Extract non-string keys before mapstructure decode.
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed OPConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("op backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("op backend: invalid settings: %w", err)
	}

	// Extract env lookup from settings.
	var envFn llmcontext.Lookup
	if v, ok := cfg.Settings["env"]; ok {
		if fn, ok := v.(func(string) string); ok {
			envFn = fn
		} else if lk, ok := v.(llmcontext.Lookup); ok {
			envFn = lk
		}
	}

	return Open(Options{
		Vault:  typed.Vault,
		Bin:    typed.Bin,
		Runner: kexec.DefaultRunner,
		Env:    envFn,
	})
}
