// Package lastpass implements the LastPass backend for keylatch.
// register.go self-registers the lastpass backend in backend.Default via init().
package lastpass

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// LastPassConfig holds the typed configuration for the LastPass backend.
type LastPassConfig struct {
	// Bin is the explicit path to the `lpass` binary. Optional.
	Bin string `mapstructure:"bin"`

	// Username is the LastPass account email. Optional.
	Username string `mapstructure:"username"`
}

func init() {
	if err := backend.Default.Register("lastpass", lastpassFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/lastpass: %w", err))
	}
}

func lastpassFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed LastPassConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("lastpass backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("lastpass backend: invalid settings: %w", err)
	}

	return Open(Options{
		Bin:      typed.Bin,
		Username: typed.Username,
		Runner:   kexec.DefaultRunner,
	})
}
