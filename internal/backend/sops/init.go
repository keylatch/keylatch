package sops

import (
	"context"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
)

// Config is the typed configuration of the sops backend.
type Config struct {
	File       string `mapstructure:"file"`
	Format     string `mapstructure:"format"`
	AgeKey     string `mapstructure:"age_key"`
	AgeKeyFile string `mapstructure:"age_key_file"`
	// VerifyMAC is "false" to skip the whole-file MAC check; anything else, or
	// nothing, verifies it.
	VerifyMAC string `mapstructure:"verify_mac"`
}

func init() {
	if err := backend.Default.Register("sops", factory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/sops: %w", err))
	}
}

func factory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	var typed Config
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{Result: &typed, ErrorUnused: true})
	if err != nil {
		return nil, fmt.Errorf("sops backend: create decoder: %w", err)
	}
	if err := decoder.Decode(backend.StripNonStringSettings(cfg.Settings)); err != nil {
		return nil, fmt.Errorf("sops backend: invalid settings: %w", err)
	}
	return Open(Options{
		File:       typed.File,
		Format:     Format(typed.Format),
		AgeKey:     typed.AgeKey,
		AgeKeyFile: typed.AgeKeyFile,
		SkipMAC:    strings.EqualFold(typed.VerifyMAC, "false"),
	})
}
