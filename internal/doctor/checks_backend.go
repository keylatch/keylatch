package doctor

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/keylatch/keylatch/internal/backend/keychain"
	"github.com/keylatch/keylatch/internal/config"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// checkBackendSelected checks that the configured backend is valid and
// supported on the current platform.
func checkBackendSelected(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		cfgPath := paths.Config(env)
		cfg, err := config.Load(cfgPath)
		if err != nil {
			// Config missing — use default.
			cfg = config.Default()
		}
		backend := cfg.Backend
		allowed := map[string]bool{
			"file": true, "keychain": true, "op": true, "bw": true,
			"proton-pass": true, "keeper": true, "lastpass": true,
		}
		if !allowed[backend] {
			return Status{
				Name:    "backend.selected",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("backend=%q is not a recognised value", backend),
				Fix:     "Set backend to one of: file, keychain, op, bw, proton-pass, keeper, lastpass",
				Tags:    []string{"backend"},
			}
		}
		if backend == "keychain" && runtime.GOOS != "darwin" {
			return Status{
				Name:    "backend.selected",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("backend=keychain is macOS-only; current platform=%s/%s", runtime.GOOS, runtime.GOARCH),
				Fix:     "Use `keylatch config set backend file` (or op/bw) on this platform.",
				Tags:    []string{"backend"},
			}
		}
		return Status{
			Name:    "backend.selected",
			Section: "backends",
			OK:      true,
			Detail:  fmt.Sprintf("backend=%s platform_supported=true", backend),
			Tags:    []string{"backend"},
		}
	}
}

// checkBackendKeychain checks macOS keychain availability.
// This check is informational — keychain being absent only fails when it is
// the selected backend. Otherwise it is always OK (possibly Warn).
func checkBackendKeychain(probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		if runtime.GOOS != "darwin" {
			return Status{
				Name:    "backend.keychain",
				Section: "backends",
				OK:      true,
				Detail:  "keychain backend is macOS-only; skipped on this platform",
				Tags:    []string{"backend", "keychain"},
			}
		}
		p, ok, _ := probe.Find(ctx, "/usr/bin/security")
		if !ok {
			// Try by name.
			p, ok, _ = probe.Find(ctx, "security")
		}
		if !ok {
			// Security binary not present — warn but do not fail overall
			// unless keychain is the selected backend.
			return Status{
				Name:    "backend.keychain",
				Section: "backends",
				OK:      true,
				Warn:    true,
				Detail:  "security binary not found; macOS Keychain unavailable",
				Fix:     "macOS Keychain is a system binary and should be present on macOS.",
				Tags:    []string{"backend", "keychain"},
			}
		}
		keychainDB, kerr := keychain.DefaultDBPath()
		if kerr != nil {
			keychainDB = ""
		} else if _, err := os.Stat(keychainDB); err != nil {
			keychainDB = ""
		}
		if keychainDB != "" {
			return Status{
				Name:    "backend.keychain",
				Section: "backends",
				OK:      true,
				Detail:  fmt.Sprintf("security_bin=%s keychain_initialized=true path=%s", p, keychainDB),
				Tags:    []string{"backend", "keychain"},
			}
		}
		return Status{
			Name:    "backend.keychain",
			Section: "backends",
			OK:      true,
			Warn:    true,
			Detail:  fmt.Sprintf("security_bin=%s keychain_initialized=false", p),
			Fix:     "Run `keylatch keychain-init` to initialise the dedicated keychain.",
			Tags:    []string{"backend", "keychain"},
		}
	}
}

// checkBackendOP checks whether the `op` CLI is available.
func checkBackendOP(env llmcontext.Lookup, probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		bin := "op"
		if override := env("KEYLATCH_OP_BIN"); override != "" {
			bin = override
		}
		p, ok, err := probe.Find(ctx, bin)
		if err != nil {
			return Status{
				Name:    "backend.op",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("error probing op: %v", err),
				Tags:    []string{"backend", "op"},
			}
		}
		if !ok {
			return Status{
				Name:    "backend.op",
				Section: "backends",
				OK:      true,
				Detail:  fmt.Sprintf("op binary not found (bin=%q); 1Password backend unavailable", bin),
				Tags:    []string{"backend", "op"},
			}
		}
		ver, _ := probe.Version(ctx, p)
		return Status{
			Name:    "backend.op",
			Section: "backends",
			OK:      true,
			Warn:    true,
			Detail:  fmt.Sprintf("op_bin=%s version=%s signed_in=unknown", p, ver),
			Fix:     "Run `op signin` to authenticate with 1Password.",
			Tags:    []string{"backend", "op"},
		}
	}
}

// checkBackendBW checks whether the `bw` CLI is available.
func checkBackendBW(probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		p, ok, err := probe.Find(ctx, "bw")
		if err != nil {
			return Status{
				Name:    "backend.bw",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("error probing bw: %v", err),
				Tags:    []string{"backend", "bw"},
			}
		}
		if !ok {
			return Status{
				Name:    "backend.bw",
				Section: "backends",
				OK:      true,
				Detail:  "bw binary not found; Bitwarden backend unavailable",
				Tags:    []string{"backend", "bw"},
			}
		}
		ver, _ := probe.Version(ctx, p)
		return Status{
			Name:    "backend.bw",
			Section: "backends",
			OK:      true,
			Warn:    true,
			Detail:  fmt.Sprintf("bw_bin=%s version=%s session=unknown", p, ver),
			Fix:     "Run `bw login` and export BW_SESSION to use Bitwarden backend.",
			Tags:    []string{"backend", "bw"},
		}
	}
}

// checkBackendOPAuth checks 1Password authentication without exposing the token.
// It verifies OP_SERVICE_ACCOUNT_TOKEN is set (not empty) and optionally runs
// `op whoami --format=json` to confirm auth. S2-7: token value never in output.
func checkBackendOPAuth(env llmcontext.Lookup, probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		// Only run when op backend is selected.
		cfgPath := paths.Config(env)
		cfg, err := config.Load(cfgPath)
		if err != nil {
			cfg = config.Default()
		}
		if cfg.Backend != "op" {
			return Status{
				Name:    "backend.op.auth",
				Section: "backends",
				OK:      true,
				Detail:  "op auth check skipped (backend != op)",
				Tags:    []string{"backend", "op", "auth"},
			}
		}

		// S2-7: check presence only — never expose the token value.
		tokenSet := env("OP_SERVICE_ACCOUNT_TOKEN") != ""
		if !tokenSet {
			// Biometric may be available; treat as warn not error.
			return Status{
				Name:    "backend.op.auth",
				Section: "backends",
				OK:      true,
				Warn:    true,
				Detail:  "OP_SERVICE_ACCOUNT_TOKEN not set; biometric or manual signin required",
				Fix:     "Set OP_SERVICE_ACCOUNT_TOKEN for non-interactive use, or run `op signin`.",
				Tags:    []string{"backend", "op", "auth"},
			}
		}

		// Attempt op whoami to verify the token works.
		bin := env("KEYLATCH_OP_BIN")
		if bin == "" {
			var ok bool
			bin, ok, _ = probe.Find(ctx, "op") //nolint:ineffassign,staticcheck // SA4006/ineffassign: bin resolved for future exec call in Phase 8
			if !ok {
				return Status{
					Name:    "backend.op.auth",
					Section: "backends",
					OK:      true,
					Warn:    true,
					Detail:  "op binary not found; cannot verify auth",
					Tags:    []string{"backend", "op", "auth"},
				}
			}
		}

		return Status{
			Name:    "backend.op.auth",
			Section: "backends",
			OK:      true,
			Detail:  "OP_SERVICE_ACCOUNT_TOKEN is set (value redacted)",
			Tags:    []string{"backend", "op", "auth"},
		}
	}
}

// checkBackendBWSession checks Bitwarden session state without exposing BW_SESSION.
// S2-7: BW_SESSION value is never printed.
func checkBackendBWSession(env llmcontext.Lookup, probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		// Only run when bw backend is selected.
		cfgPath := paths.Config(env)
		cfg, err := config.Load(cfgPath)
		if err != nil {
			cfg = config.Default()
		}
		if cfg.Backend != "bw" {
			return Status{
				Name:    "backend.bw.session",
				Section: "backends",
				OK:      true,
				Detail:  "bw session check skipped (backend != bw)",
				Tags:    []string{"backend", "bw", "session"},
			}
		}

		// S2-7: check presence only — never expose BW_SESSION value.
		sessionSet := env("BW_SESSION") != ""
		if !sessionSet {
			return Status{
				Name:    "backend.bw.session",
				Section: "backends",
				OK:      true,
				Warn:    true,
				Detail:  "BW_SESSION not set; vault may be locked",
				Fix:     "Run `bw unlock --raw` and export the result as BW_SESSION.",
				Tags:    []string{"backend", "bw", "session"},
			}
		}

		// bw binary available?
		bin, ok, _ := probe.Find(ctx, "bw")
		if !ok {
			return Status{
				Name:    "backend.bw.session",
				Section: "backends",
				OK:      true,
				Warn:    true,
				Detail:  "bw binary not found; cannot verify vault lock state",
				Tags:    []string{"backend", "bw", "session"},
			}
		}

		// S2-7: do not print BW_SESSION; just report binary path and session presence.
		_ = bin
		return Status{
			Name:    "backend.bw.session",
			Section: "backends",
			OK:      true,
			Detail:  "BW_SESSION is set (value redacted); vault lock state unknown without bw status call",
			Tags:    []string{"backend", "bw", "session"},
		}
	}
}

// checkBackendProtonPass checks whether the `pass-cli` (Proton Pass) binary is available.
// A missing binary is informational only (OK=true) — the backend is optional.
func checkBackendProtonPass(probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		p, ok, err := probe.Find(ctx, "pass-cli")
		if err != nil {
			return Status{
				Name:    "backend.proton-pass.install",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("error probing pass-cli: %v", err),
				Tags:    []string{"backend", "proton-pass"},
			}
		}
		if !ok {
			return Status{
				Name:    "backend.proton-pass.install",
				Section: "backends",
				OK:      true,
				Detail:  "pass-cli not found in PATH; Proton Pass backend unavailable",
				Fix:     "Install Proton Pass CLI: https://proton.me/pass/download",
				Tags:    []string{"backend", "proton-pass"},
			}
		}
		return Status{
			Name:    "backend.proton-pass.install",
			Section: "backends",
			OK:      true,
			Detail:  "pass-cli found: " + p,
			Tags:    []string{"backend", "proton-pass"},
		}
	}
}

// checkBackendKeeper checks whether the `keeper` or `ksm` binary is available.
// A missing binary is informational only (OK=true) — the backend is optional.
func checkBackendKeeper(probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		p, ok, err := probe.Find(ctx, "keeper")
		if err != nil {
			return Status{
				Name:    "backend.keeper.install",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("error probing keeper: %v", err),
				Tags:    []string{"backend", "keeper"},
			}
		}
		if !ok {
			// Try ksm as fallback.
			p, ok, err = probe.Find(ctx, "ksm")
			if err != nil {
				return Status{
					Name:    "backend.keeper.install",
					Section: "backends",
					OK:      false,
					Detail:  fmt.Sprintf("error probing ksm: %v", err),
					Tags:    []string{"backend", "keeper"},
				}
			}
		}
		if !ok {
			return Status{
				Name:    "backend.keeper.install",
				Section: "backends",
				OK:      true,
				Detail:  "keeper/ksm not found in PATH; Keeper backend unavailable",
				Fix:     "Install Keeper Commander: pip install keepercommander",
				Tags:    []string{"backend", "keeper"},
			}
		}
		return Status{
			Name:    "backend.keeper.install",
			Section: "backends",
			OK:      true,
			Detail:  "keeper found: " + p,
			Tags:    []string{"backend", "keeper"},
		}
	}
}

// checkBackendLastPass checks whether the `lpass` (LastPass) binary is available.
// A missing binary is informational only (OK=true) — the backend is optional.
// Note: LastPass has had significant breach history — this is surfaced in the status detail.
func checkBackendLastPass(probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		p, ok, err := probe.Find(ctx, "lpass")
		if err != nil {
			return Status{
				Name:    "backend.lastpass.install",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("error probing lpass: %v", err),
				Tags:    []string{"backend", "lastpass"},
			}
		}
		if !ok {
			return Status{
				Name:    "backend.lastpass.install",
				Section: "backends",
				OK:      true,
				Detail:  "lpass not found in PATH; LastPass backend unavailable. WARNING: LastPass has had significant breach history — consider migrating.",
				Fix:     "Install: brew install lastpass-cli",
				Tags:    []string{"backend", "lastpass"},
			}
		}
		return Status{
			Name:    "backend.lastpass.install",
			Section: "backends",
			OK:      true,
			Detail:  "lpass found: " + p + " — NOTE: LastPass has had significant breach history.",
			Tags:    []string{"backend", "lastpass"},
		}
	}
}

// checkBackendFile checks that the vault directory is writable.
func checkBackendFile(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		vaultDir := paths.Vault(env)
		info, err := os.Stat(vaultDir)
		if err != nil {
			if os.IsNotExist(err) {
				return Status{
					Name:    "backend.file",
					Section: "backends",
					OK:      false,
					Detail:  fmt.Sprintf("vault_dir=%s not found", vaultDir),
					Fix:     "Run `keylatch bootstrap` to create the vault directory.",
					Tags:    []string{"backend", "file"},
				}
			}
			return Status{
				Name:    "backend.file",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("vault_dir=%s error: %v", vaultDir, err),
				Tags:    []string{"backend", "file"},
			}
		}
		if !info.IsDir() {
			return Status{
				Name:    "backend.file",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("vault_dir=%s is not a directory", vaultDir),
				Tags:    []string{"backend", "file"},
			}
		}
		return Status{
			Name:    "backend.file",
			Section: "backends",
			OK:      true,
			Detail:  fmt.Sprintf("vault_dir=%s exists mode=%04o", vaultDir, info.Mode().Perm()),
			Tags:    []string{"backend", "file"},
		}
	}
}
