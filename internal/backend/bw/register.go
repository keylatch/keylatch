// Package bw implements the Bitwarden backend for keylatch.
// register.go self-registers the bw backend in backend.Default via init().
package bw

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// BWConfig holds the typed configuration for the Bitwarden backend.
type BWConfig struct {
	// Server is the Vaultwarden self-hosted URL (https:// required). Optional.
	Server string `mapstructure:"server"`

	// Folder filters items by folder name. Optional.
	Folder string `mapstructure:"folder"`

	// Collection filters items by collection name. Optional.
	Collection string `mapstructure:"collection"`

	// Bin is the explicit path to the `bw` binary. Optional.
	Bin string `mapstructure:"bin"`
}

func init() {
	if err := backend.Default.Register("bw", bwFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/bw: %w", err))
	}
}

func bwFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	// Extract non-string keys before mapstructure decode.
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed BWConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("bw backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("bw backend: invalid settings: %w", err)
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
		Server:     typed.Server,
		Folder:     typed.Folder,
		Collection: typed.Collection,
		Bin:        typed.Bin,
		Runner:     kexec.DefaultRunner,
		Env:        envFn,
	})
}
