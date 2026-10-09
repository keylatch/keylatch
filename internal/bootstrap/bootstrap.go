// Package bootstrap implements idempotent first-run initialization of the
// keylatch configuration directory structure. It creates the config dir,
// vault dir, audit log, config file, and cryptographic keyring with correct
// file modes.
//
// Security invariant all dirs created with 0o700, all files with 0o600.
// Security invariant running twice produces all noop steps.
// Security invariant bootstrap initialises the keyring/KEK so the
// file backend can operate without a separate setup step.
package bootstrap

import (
	"context"
	"crypto/rand"
	"errors"
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
	// InsecureFileKEK keeps the vault identity in a plaintext file next to
	// the vault instead of an OS keyring. KEYLATCH_INSECURE_FILE_KEK=1 is
	// equivalent.
	InsecureFileKEK bool
	// IdentityStore overrides the OS keyring; nil selects the platform default.
	IdentityStore kek.IdentityStore
}

// PlanStep describes a single action that bootstrap will take (or skipped as noop).
type PlanStep struct {
	Action string      // "mkdir" | "writeFile" | "keyringStore" | "acknowledge" | "noop"
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
		// do not overwrite existing config.
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
		store := opts.IdentityStore
		if store == nil {
			store = kek.DefaultIdentityStore()
		}
		vi := kek.VaultIdentity{Path: paths.KeyringIdentityPath(env), Store: store}
		insecure := opts.InsecureFileKEK || kek.InsecureFileKEKRequested(env)

		if err := planMkdir(&plan, krDir, opts.DryRun); err != nil {
			return plan, fmt.Errorf("keyring dir: %w", err)
		}
		if err := planIdentity(&plan, vi, insecure, opts.DryRun, opts.Force); err != nil {
			return plan, fmt.Errorf("vault identity: %w", err)
		}
		if err := planWriteKeyring(&plan, krPath, vi, opts.DryRun, opts.Force); err != nil {
			return plan, fmt.Errorf("keyring: %w", err)
		}
	}

	return plan, nil
}

const insecureFileKEKWarning = "INSECURE: the vault key is stored in plaintext at %s. Any process running as your user can copy it and decrypt the vault offline. Use an OS keyring (macOS Keychain or a Secret Service such as GNOME Keyring/KWallet) and rerun `keylatch bootstrap` without --insecure-file-kek to move it there."

const noKeyringHint = "rerun with --insecure-file-kek (or KEYLATCH_INSECURE_FILE_KEK=1) to keep the vault key in a plaintext file next to the vault; any process running as your user can then decrypt the vault"

// planIdentity provisions the vault identity, preferring the OS keyring, and
// moves a plaintext identity from an older install into the keyring.
func planIdentity(plan *Plan, vi kek.VaultIdentity, insecure, dryRun, force bool) error {
	loc, onDisk, err := vi.Location()
	if err != nil {
		return err
	}
	removed := false
	if force && loc != kek.IdentityMissing {
		if !dryRun {
			if err := vi.Remove(); err != nil {
				return fmt.Errorf("remove existing identity: %w", err)
			}
		}
		loc, onDisk, removed = kek.IdentityMissing, false, true
	}

	switch loc {
	case kek.IdentityMissing:
		return planProvisionIdentity(plan, vi, insecure, dryRun, removed)

	case kek.IdentityInKeyring:
		if onDisk && !dryRun {
			if _, err := vi.MigrateToKeyring(); err != nil {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("a plaintext vault identity remains at %s: %v", vi.Path, err))
			}
		}
		plan.Steps = append(plan.Steps, PlanStep{Action: "noop", Path: vi.RefPath(), Mode: 0o600, Reason: "vault identity is held in the OS keyring", Done: true})
		return nil

	case kek.IdentityInFileAcknowledged:
		if insecure {
			plan.Steps = append(plan.Steps, PlanStep{Action: "noop", Path: vi.Path, Mode: 0o600, Reason: "plaintext vault identity (--insecure-file-kek)", Done: true})
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(insecureFileKEKWarning, vi.Path))
			return nil
		}
		return planMigrateIdentity(plan, vi, dryRun)

	default: // kek.IdentityInFileUnacknowledged
		if insecure {
			if !dryRun {
				if err := vi.Acknowledge(); err != nil {
					return fmt.Errorf("record --insecure-file-kek: %w", err)
				}
			}
			plan.Steps = append(plan.Steps, PlanStep{Action: "acknowledge", Path: vi.InsecureMarkerPath(), Mode: 0o600, Reason: "record opt-in to the plaintext vault identity", Done: !dryRun})
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(insecureFileKEKWarning, vi.Path))
			return nil
		}
		return planMigrateIdentity(plan, vi, dryRun)
	}
}

func planProvisionIdentity(plan *Plan, vi kek.VaultIdentity, insecure, dryRun, replaced bool) error {
	if insecure {
		if !dryRun {
			if err := vi.Provision(true); err != nil {
				return err
			}
		}
		reason := "create plaintext vault identity (--insecure-file-kek)"
		if replaced {
			reason = "force re-create plaintext vault identity (--insecure-file-kek)"
		}
		plan.Steps = append(plan.Steps, PlanStep{Action: "writeFile", Path: vi.Path, Mode: 0o600, Reason: reason, Done: !dryRun})
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(insecureFileKEKWarning, vi.Path))
		return nil
	}

	storeName := "OS keyring"
	if vi.Store != nil {
		storeName = vi.Store.Name()
	}
	if !dryRun {
		if err := vi.Provision(false); err != nil {
			if errors.Is(err, kek.ErrNoOSKeyring) {
				return fmt.Errorf("%w; %s", err, noKeyringHint)
			}
			return err
		}
	} else if vi.Store == nil {
		plan.Warnings = append(plan.Warnings, "no OS keyring detected; "+noKeyringHint)
	}
	reason := "store vault identity in " + storeName
	if replaced {
		reason = "force re-create vault identity in " + storeName
	}
	plan.Steps = append(plan.Steps, PlanStep{Action: "keyringStore", Path: vi.RefPath(), Mode: 0o600, Reason: reason, Done: !dryRun})
	return nil
}

func planMigrateIdentity(plan *Plan, vi kek.VaultIdentity, dryRun bool) error {
	if dryRun {
		if vi.Store == nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("plaintext vault identity at %s and no OS keyring detected; %s", vi.Path, noKeyringHint))
		}
		plan.Steps = append(plan.Steps, PlanStep{Action: "keyringStore", Path: vi.RefPath(), Mode: 0o600, Reason: "move plaintext vault identity into the OS keyring", Done: false})
		return nil
	}
	if _, err := vi.MigrateToKeyring(); err != nil {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("vault identity is still stored in plaintext at %s (%v); %s", vi.Path, err, noKeyringHint))
		plan.Steps = append(plan.Steps, PlanStep{Action: "noop", Path: vi.Path, Mode: 0o600, Reason: "plaintext vault identity could not be moved into the OS keyring", Done: true})
		return nil
	}
	plan.Steps = append(plan.Steps, PlanStep{Action: "keyringStore", Path: vi.RefPath(), Mode: 0o600, Reason: "moved plaintext vault identity into " + vi.Store.Name() + " and removed the file", Done: true})
	return nil
}

// planWriteKeyring creates keyring.json at krPath, wrapped by the KEK derived
// from the vault identity. When force is true, an existing keyring is removed
// and recreated.
func planWriteKeyring(plan *Plan, krPath string, vi kek.VaultIdentity, dryRun, force bool) error {
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

		k, err := vi.KEK(salt)
		if err != nil {
			return fmt.Errorf("derive KEK: %w", err)
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
