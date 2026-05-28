// Package vault implements the HashiCorp Vault backend for keylatch.
// init.go self-registers the vault backend in backend.Default via init().
package vault

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
)

// VaultConfig holds the typed configuration for the HashiCorp Vault backend.
type VaultConfig struct {
	Address   string `mapstructure:"address"`    // e.g. http://127.0.0.1:8200
	Token     string `mapstructure:"token"`      // static token auth
	RoleID    string `mapstructure:"role_id"`    // AppRole auth
	SecretID  string `mapstructure:"secret_id"`  // AppRole auth
	Mount     string `mapstructure:"mount"`      // default "secret"
	KVVersion string `mapstructure:"kv_version"` // "1" or "2"; default "2"
	Namespace string `mapstructure:"namespace"`  // Vault Enterprise
}

func init() {
	if err := backend.Default.Register("vault", vaultFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/vault: %w", err))
	}
}

func vaultFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed VaultConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("vault backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("vault backend: invalid settings: %w", err)
	}

	kvVersion := 2
	if typed.KVVersion == "1" {
		kvVersion = 1
	}

	return Open(Options{
		Address:   typed.Address,
		Token:     typed.Token,
		RoleID:    typed.RoleID,
		SecretID:  typed.SecretID,
		Mount:     typed.Mount,
		KVVersion: kvVersion,
		Namespace: typed.Namespace,
	})
}
