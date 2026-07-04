// Package bootstrap implements idempotent first-run initialization of the
// keylatch configuration directory structure. It creates the config dir,
// vault dir, audit log, config file, and cryptographic keyring with correct
// file modes.
//
// Security invariant S05-1: all dirs created with 0o700, all files with 0o600.
// Security invariant S05-2: running twice produces all noop steps.
// Security invariant T-02-04: bootstrap initialises the keyring/KEK so the
// file backend can operate without a separate setup step.
package bootstrap

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"strings"

	backendpkg "github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// Options controls bootstrap behavior.
type Options struct {
	DryRun  bool
	JSON    bool
	Backend string // "file" (default) | "keychain" | "op" | "bw"
	Env     llmcontext.Lookup
	// Force re-initializes the keyring even if one already exists.
	// Used by `keylatch bootstrap --force`. Prompts for confirmation unless
	// Confirm is set to true (for tests).
	Force   bool
	Confirm bool // skip the [y/N] prompt when Force=true
}

// PlanStep describes a single action that bootstrap will take (or skipped as noop).
type PlanStep struct {
	Action string      // "mkdir" | "writeFile" | "chmod" | "noop"
	Path   string      // absolute path
	Mode   os.FileMode // target permission
	Reason string      // human-readable description
	Done   bool        // false during --dry-run
}

// Plan is the result of a bootstrap run — the full list of steps and any warnings.
type Plan struct {
	Steps    []PlanStep
	Warnings []string
}

// UnknownBackend is returned when an unsupported backend is specified.
type UnknownBackend struct {
	Backend string
}

func (e *UnknownBackend) Error() string {
	return fmt.Sprintf("unknown backend %q: allowed values are %s", e.Backend, strings.Join(backendpkg.KnownCanonicalNames(), ", "))
}

// Run executes or plans the bootstrap steps. It is idempotent — running on a
// directory that already exists produces only noop steps.
func Run(_ context.Context, opts Options) (Plan, error) {
	// Enforce caller confirmation contract: library callers must not set Force=true
	// without also setting Confirm=true, which documents that they have obtained user
	// consent before calling. The CLI sets Confirm=true only after the prompt passes.
	if opts.Force && !opts.Confirm {
		return Plan{}, fmt.Errorf("bootstrap: --force requires Confirm=true; the caller must obtain user confirmation before setting this flag")
	}

	// Resolve env lookup.
	env := opts.Env
	if env == nil {
		env = os.Getenv
	}

	// Default backend.
	backendName := opts.Backend
	if backendName == "" {
		backendName = "file"
	}

	// Validate backend.
	canonicalBackend, ok := backendpkg.CanonicalName(backendName)
	if !ok {
		return Plan{}, &UnknownBackend{Backend: backendName}
	}
	backendName = canonicalBackend

	// keychain is macOS-only.
	if backendName == "keychain" && runtime.GOOS != "darwin" {
		return Plan{}, fmt.Errorf("keychain backend is macOS-only; use file, op, bw, or another external backend on %s", runtime.GOOS)
	}

	var plan Plan

	// Resolve paths.
	configDir := paths.ConfigDir(env)
	vaultDir := paths.Vault(env)
	auditFile := paths.Audit(env)
	configFile := paths.Config(env)

	// Step 1: create config dir.
	if err := planMkdir(&plan, configDir, opts.DryRun); err != nil {
		return plan, fmt.Errorf("config dir: %w", err)
	}

	// Step 2: create vault dir.
	if err := planMkdir(&plan, vaultDir, opts.DryRun); err != nil {
		return plan, fmt.Errorf("vault dir: %w", err)
	}

	// Step 3: create audit log (empty if not exists).
	if err := planWriteFile(&plan, auditFile, nil, 0o600, opts.DryRun); err != nil {
		return plan, fmt.Errorf("audit file: %w", err)
	}

	// Step 4: create config file with defaults.
	cfg := config.Default()
	cfg.Backend = backendName

	cfgExists, err := fileExists(configFile)
	if err != nil {
		return plan, fmt.Errorf("check config file: %w", err)
	}
	if cfgExists {
		// S05-7: do not overwrite existing config.
		// Check if it has a different version — if so, warn.
		existing, loadErr := config.Load(configFile)
		if loadErr != nil {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("existing config at %s is unreadable: %v; skipping overwrite", configFile, loadErr))
		} else if existing.Version != 1 {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("existing config at %s has version %d (current: 1); skipping overwrite", configFile, existing.Version))
		}
		plan.Steps = append(plan.Steps, PlanStep{
			Action: "noop",
			Path:   configFile,
			Mode:   0o600,
			Reason: "config.json already exists",
			Done:   true,
		})
	} else {
		if !opts.DryRun {
			if err := config.Save(configFile, cfg); err != nil {
				return plan, fmt.Errorf("save config: %w", err)
			}
		}
		plan.Steps = append(plan.Steps, PlanStep{
			Action: "writeFile",
			Path:   configFile,
			Mode:   0o600,
			Reason: "create default config.json",
			Done:   !opts.DryRun,
		})
	}

	// Steps 5–7: initialize the cryptographic keyring.
	// Only performed for the "file" backend — other backends manage their own key storage.
	if backendName == "file" {
		krDir := paths.KeyringDir(env)
		krPath := paths.KeyringPath(env)
		identityPath := paths.KeyringIdentityPath(env)

		// Step 5: create keyring directory.
		if err := planMkdir(&plan, krDir, opts.DryRun); err != nil {
			return plan, fmt.Errorf("keyring dir: %w", err)
		}

		// Step 6: create the age-env identity file if it does not exist.
		// If --force is set, the existing identity file is removed before recreating.
		if err := planWriteIdentity(&plan, identityPath, opts.DryRun, opts.Force); err != nil {
			return plan, fmt.Errorf("keyring identity: %w", err)
		}

		// Step 7: create keyring.json if it does not exist.
		// If --force is set, the existing keyring is removed before recreating.
		if err := planWriteKeyring(&plan, krPath, identityPath, opts.DryRun, opts.Force); err != nil {
			return plan, fmt.Errorf("keyring: %w", err)
		}
	}

	return plan, nil
}

// planWriteIdentity creates a random age-env identity file at path.
// On macOS the keychain is the preferred KEK source; the identity file is the
// portable fallback for environments without a platform keystore.
// When force is true, an existing identity file is removed before recreating.
func planWriteIdentity(plan *Plan, path string, dryRun, force bool) error {
	exists, err := fileExists(path)
	if err != nil {
		return err
	}
	if exists && !force {
		plan.Steps = append(plan.Steps, PlanStep{
			Action: "noop",
			Path:   path,
			Mode:   0o600,
			Reason: "keyring identity file already exists",
			Done:   true,
		})
		return nil
	}

	if !dryRun {
		// Remove existing identity file when force is set.
		if exists && force {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove existing identity %q: %w", path, err)
			}
		}
		// Generate 32 random bytes as the identity material.
		identity := make([]byte, 32)
		if _, err := rand.Read(identity); err != nil {
			return fmt.Errorf("generate identity: %w", err)
		}
		if err := os.WriteFile(path, identity, 0o600); err != nil {
			return fmt.Errorf("write identity %q: %w", path, err)
		}
	}
	reason := "create age-env keyring identity (fallback KEK source)"
	if force && exists {
		reason = "force re-create age-env keyring identity"
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Action: "writeFile",
		Path:   path,
		Mode:   0o600,
		Reason: reason,
		Done:   !dryRun,
	})
	return nil
}

// planWriteKeyring creates a keyring.json at krPath using identityPath as the KEK source.
// On macOS the keychain KEK is tried first; on failure or on non-darwin platforms,
// the age-env identity file is used.
// When force is true, an existing keyring is removed and recreated.
func planWriteKeyring(plan *Plan, krPath, identityPath string, dryRun, force bool) error {
	exists, err := fileExists(krPath)
	if err != nil {
		return err
	}
	if exists && !force {
		plan.Steps = append(plan.Steps, PlanStep{
			Action: "noop",
			Path:   krPath,
			Mode:   0o600,
			Reason: "keyring.json already exists",
			Done:   true,
		})
		return nil
	}

	if !dryRun {
		// Remove existing keyring when force is set.
		if exists && force {
			if err := os.Remove(krPath); err != nil {
				return fmt.Errorf("remove existing keyring %q: %w", krPath, err)
			}
		}

		// Generate a random salt for the keyring.
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("generate keyring salt: %w", err)
		}

		// Select KEK: try keychain on macOS first; fall back to age-env identity.
		var k kek.KEK
		if runtime.GOOS == "darwin" {
			k, err = kek.KeychainKEK("keylatch-vault-kek")
		}
		if err != nil || k == nil {
			// macOS keychain unavailable or non-darwin platform — use age-env identity.
			k, err = kek.AgeIdentityKEKFromPath(identityPath, salt)
			if err != nil {
				return fmt.Errorf("derive age-env KEK: %w", err)
			}
		}

		if err := keyring.NewWithSalt(krPath, k, envelope.XChaCha20Poly1305, 0, salt); err != nil {
			return fmt.Errorf("write keyring %q: %w", krPath, err)
		}
	}
	reason := "create keyring.json (cryptographic key ring)"
	if force && exists {
		reason = "force re-create keyring.json (destroying previous keyring)"
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Action: "writeFile",
		Path:   krPath,
		Mode:   0o600,
		Reason: reason,
		Done:   !dryRun,
	})
	return nil
}

// planMkdir adds a mkdir or noop step to plan. If not dry-run, creates the dir.
func planMkdir(plan *Plan, p string, dryRun bool) error {
	info, err := os.Stat(p)
	if err == nil {
		// Already exists.
		if !info.IsDir() {
			return fmt.Errorf("%q exists but is not a directory", p)
		}
		plan.Steps = append(plan.Steps, PlanStep{
			Action: "noop",
			Path:   p,
			Mode:   0o700,
			Reason: "directory already exists",
			Done:   true,
		})
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("stat %q: %w", p, err)
	}

	// Does not exist — create it.
	if !dryRun {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return fmt.Errorf("mkdir %q: %w", p, err)
		}
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Action: "mkdir",
		Path:   p,
		Mode:   0o700,
		Reason: "create directory",
		Done:   !dryRun,
	})
	return nil
}

// planWriteFile adds a writeFile or noop step. Creates the file only if absent.
func planWriteFile(plan *Plan, p string, content []byte, mode os.FileMode, dryRun bool) error {
	exists, err := fileExists(p)
	if err != nil {
		return err
	}
	if exists {
		plan.Steps = append(plan.Steps, PlanStep{
			Action: "noop",
			Path:   p,
			Mode:   mode,
			Reason: "file already exists",
			Done:   true,
		})
		return nil
	}

	if !dryRun {
		if err := os.WriteFile(p, content, mode); err != nil {
			return fmt.Errorf("write %q: %w", p, err)
		}
	}
	plan.Steps = append(plan.Steps, PlanStep{
		Action: "writeFile",
		Path:   p,
		Mode:   mode,
		Reason: "create file",
		Done:   !dryRun,
	})
	return nil
}

// fileExists returns true if path exists as a regular file.
func fileExists(p string) (bool, error) {
	info, err := os.Stat(p)
	if err == nil {
		return !info.IsDir(), nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat %q: %w", p, err)
}
