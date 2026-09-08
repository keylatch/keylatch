//go:build darwin

// Package keychain implements the macOS Keychain backend.
// register.go self-registers the keychain backend in backend.Default via init().
package keychain

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/manifest"
)

// KeychainConfig holds the typed configuration for the keychain backend.
// All fields are optional — defaults are applied inside Open.
type KeychainConfig struct {
	KeychainPath string `mapstructure:"keychain_path"`
	LockPath     string `mapstructure:"lock_path"`
	SecurityBin  string `mapstructure:"security_bin"`
}

func init() {
	if err := backend.Default.Register("keychain", keychainFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/keychain: %w", err))
	}
}

func keychainFactory(_ context.Context, cfg backend.BackendConfig) (backend.Backend, error) {
	// M1 excludes macOS from the certified platform cohort (F16) — refuse
	// selection here too, not just via the darwin build tag, so the backend
	// stays unreachable even from a darwin build of an unreleased profile.
	if !manifest.M1().Enabled("keychain") {
		return nil, fmt.Errorf("%w: keychain is not supported in this release", backend.ErrUnavailable)
	}

	// Extract non-mapstructure keys before decoding.
	settings := backend.StripNonStringSettings(cfg.Settings)

	var typed KeychainConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      &typed,
		ErrorUnused: true,
	})
	if err != nil {
		return nil, fmt.Errorf("keychain backend: create decoder: %w", err)
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("keychain backend: invalid settings: %w", err)
	}

	// Extract env lookup from settings (passed as interface{} by dispatch).
	var envFn llmcontext.Lookup
	if v, ok := cfg.Settings["env"]; ok {
		if fn, ok := v.(func(string) string); ok {
			envFn = fn
		} else if lk, ok := v.(llmcontext.Lookup); ok {
			envFn = lk
		}
	}

	return Open(Options{
		KeychainPath: typed.KeychainPath,
		LockPath:     typed.LockPath,
		SecurityBin:  typed.SecurityBin,
		Runner:       kexec.DefaultRunner,
		Env:          envFn,
	})
}
