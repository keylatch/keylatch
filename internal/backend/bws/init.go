package bws

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// Config is the typed configuration of the Secrets Manager backend.
type Config struct {
	AccessToken string `mapstructure:"access_token"`
	ProjectID   string `mapstructure:"project_id"`
	ServerURL   string `mapstructure:"server_url"`
	Bin         string `mapstructure:"bin"`
}

func init() {
	if err := backend.Default.Register("bws", factory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/bws: %w", err))
	}
}

func factory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	var typed Config
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{Result: &typed, ErrorUnused: true})
	if err != nil {
		return nil, fmt.Errorf("bws backend: create decoder: %w", err)
	}
	if err := decoder.Decode(backend.StripNonStringSettings(cfg.Settings)); err != nil {
		return nil, fmt.Errorf("bws backend: invalid settings: %w", err)
	}
	var env llmcontext.Lookup
	if fn, ok := cfg.Settings["env"].(llmcontext.Lookup); ok {
		env = fn
	} else if fn, ok := cfg.Settings["env"].(func(string) string); ok {
		env = fn
	}
	return Open(Options{AccessToken: typed.AccessToken, ProjectID: typed.ProjectID, ServerURL: typed.ServerURL, Bin: typed.Bin, Env: env})
}
