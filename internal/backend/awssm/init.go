// Package awssm implements the AWS Secrets Manager backend for keylatch.
// init.go self-registers the aws-sm backend in backend.Default via init().
package awssm

import (
	"context"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
)

// AWSConfig holds the typed configuration for the AWS Secrets Manager backend.
type AWSConfig struct {
	Region      string `mapstructure:"region"`
	AccessKey   string `mapstructure:"access_key_id"`
	SecretKey   string `mapstructure:"secret_access_key"`
	ForceDelete string `mapstructure:"force_delete"` // "true"/"false"; was bool
}

func init() {
	if err := backend.Default.Register("aws-sm", awsSMFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/awssm: %w", err))
	}
}

func awsSMFactory(ctx context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed AWSConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-sm backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("aws-sm backend: invalid settings: %w", err)
	}

	forceDelete := strings.EqualFold(typed.ForceDelete, "true")

	return Open(ctx, Options{
		Region:      typed.Region,
		AccessKey:   typed.AccessKey,
		SecretKey:   typed.SecretKey,
		ForceDelete: forceDelete,
	})
}
