// Package dispatch selects and caches the configured backend for the lifetime
// of one keylatch process. Resolution order (first non-empty wins):
//  1. cfg.Backend (from ~/.keylatch/config.json)
//  2. KEYLATCH_BACKEND env var
//  3. default: "file"
//
// Backends are registered via init() side-effects (import the
// internal/backend/all package to pull in all built-in backends).
package dispatch

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// ErrUnknownBackend is returned when the requested backend name is not
// registered in backend.Default. Known lists the registered backend names at
// the time of the error.
type ErrUnknownBackend struct {
	Name  string
	Known []string
}

func (e ErrUnknownBackend) Error() string {
	if len(e.Known) == 0 {
		return fmt.Sprintf("unknown backend %q; no backends registered (import internal/backend/all)", e.Name)
	}
	return fmt.Sprintf("unknown backend %q; valid values: %s", e.Name, strings.Join(e.Known, ", "))
}

// nolint:gochecknoglobals
var (
	mu       sync.Mutex
	once     sync.Once
	instance backend.Backend
	initErr  error
)

// Select returns the configured Backend, instantiated once per process.
// Thread-safe; uses sync.Once for caching.
func Select(ctx context.Context, cfg config.Config, env llmcontext.Lookup) (backend.Backend, error) {
	once.Do(func() {
		instance, initErr = selectBackend(ctx, cfg, env)
	})
	return instance, initErr
}

// ClearCached clears the cached backend instance so the next call to Select
// will re-resolve the backend. Used by production commands that switch the
// active backend (e.g. keylatch keychain, keylatch op, keylatch bw).
//
// NOT goroutine-safe against concurrent Select() calls. Callers must ensure
// no Select() is in flight before calling ClearCached.
func ClearCached() {
	mu.Lock()
	defer mu.Unlock()
	once = sync.Once{} // not goroutine-safe against concurrent Select()
	instance = nil
	initErr = nil
}

// selectBackend performs the actual backend resolution (called once via Once).
func selectBackend(ctx context.Context, cfg config.Config, env llmcontext.Lookup) (backend.Backend, error) {
	// Resolution order: cfg.Backend → env("KEYLATCH_BACKEND") → "file"
	name := cfg.Backend
	if name == "" && env != nil {
		name = env("KEYLATCH_BACKEND")
	}
	if name == "" {
		name = "file"
	}

	// Build Settings from config fields so factory functions can decode them.
	settings := buildSettings(name, cfg, env)

	factory, ok := backend.Default.Get(name)
	if !ok {
		return nil, ErrUnknownBackend{Name: name, Known: backend.Default.List()}
	}

	return factory(ctx, backend.BackendConfig{Name: name, Settings: settings})
}

// buildSettings constructs the Settings map for the given backend name from
// the config and environment. Factories decode this map into typed structs.
func buildSettings(name string, cfg config.Config, env llmcontext.Lookup) map[string]interface{} {
	s := make(map[string]interface{})

	switch name {
	case "file":
		dir := cfg.DataDir
		if dir == "" && env != nil {
			dir = env("KEYLATCH_DATA_DIR")
		}
		if dir == "" {
			home, err := userHomeDir()
			// If home-dir resolution fails here, we pass data_dir="" to the factory,
			// which will attempt its own resolution and return a descriptive error.
			if err == nil {
				dir = home + "/.keylatch/vault"
			}
		}
		s["data_dir"] = dir

		// Allow KEYLATCH_KEYRING_PATH env var to override the keyring location.
		// The factory falls back to paths.KeyringPath(DefaultLookup) when this is empty.
		if env != nil {
			if krPath := env("KEYLATCH_KEYRING_PATH"); krPath != "" {
				s["keyring_path"] = krPath
			}
		}

	case "keychain":
		// keychain options are resolved from defaults inside the factory.
		// Pass runner/env references via dedicated keys.
		s["env"] = env

	case "op":
		s["env"] = env
		if cfg.OP != nil {
			s["vault"] = cfg.OP.Vault
			s["bin"] = cfg.OP.Bin
		}

	case "bw":
		s["env"] = env
		if cfg.BW != nil {
			s["server"] = cfg.BW.Server
			s["folder"] = cfg.BW.Folder
			s["collection"] = cfg.BW.Collection
			s["bin"] = cfg.BW.Bin
		}
	}

	return s
}

// userHomeDir is a thin wrapper for testing isolation.
func userHomeDir() (string, error) {
	return userHomeDirImpl()
}
