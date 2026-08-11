package doctor

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/backend/keychain"
	"github.com/keylatch/keylatch/internal/config"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// checkBackendSelected checks that the configured backend is valid and
// supported on the current platform. The allowed set is derived from
// backend.KnownCanonicalNames() (H4) rather than a hardcoded literal, so
// registering a new backend (vault, aws-sm, gcp-sm, azure-kv, doppler,
// infisical, op-connect, ...) doesn't also require a doctor update to avoid
// a spurious hard FAIL for anyone using it.
func checkBackendSelected(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		cfgPath := paths.Config(env)
		cfg, err := config.Load(cfgPath)
		if err != nil {
			// Config missing — use default.
			cfg = config.Default()
		}
		canonical, ok := backend.CanonicalName(cfg.Backend)
		if !ok {
			return Status{
				Name:    "backend.selected",
				Section: "backends",
				OK:      false,
				Detail:  fmt.Sprintf("backend=%q is not a recognised value", cfg.Backend),
				Fix:     "Set backend to one of: " + strings.Join(backend.KnownCanonicalNames(), ", "),
				Tags:    []string{"backend"},
			}
		}
		if canonical == "keychain" && runtime.GOOS != "darwin" {
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
			Detail:  fmt.Sprintf("backend=%s platform_supported=true", canonical),
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

// checkBackendOP checks whether the `op` CLI is available. It only warns
// about authentication when op is the SELECTED backend (H3) — a merely-
// installed op CLI on a machine configured to use a different backend is
// informational, not something requiring action. session=unknown/signed_in=
// unknown literals were removed rather than fabricated: real auth-state
// probing (without exposing the token) is checkBackendOPAuth's job.
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

		cfgPath := paths.Config(env)
		cfg, cfgErr := config.Load(cfgPath)
		if cfgErr != nil {
			cfg = config.Default()
		}
		if cfg.Backend != "op" {
			return Status{
				Name:    "backend.op",
				Section: "backends",
				OK:      true,
				Detail:  fmt.Sprintf("op_bin=%s version=%s (backend not selected)", p, ver),
				Tags:    []string{"backend", "op"},
			}
		}
		return Status{
			Name:    "backend.op",
			Section: "backends",
			OK:      true,
			Warn:    true,
			Detail:  fmt.Sprintf("op_bin=%s version=%s", p, ver),
			Fix:     "Run `op signin` to authenticate with 1Password.",
			Tags:    []string{"backend", "op"},
		}
	}
}

// checkBackendBW checks whether the `bw` CLI is available. See checkBackendOP
// for the H3 rationale: only warns when bw is the SELECTED backend, and
// drops the fabricated session=unknown literal.
func checkBackendBW(env llmcontext.Lookup, probe kexec.Probe) Check {
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

		cfgPath := paths.Config(env)
		cfg, cfgErr := config.Load(cfgPath)
		if cfgErr != nil {
			cfg = config.Default()
		}
		if cfg.Backend != "bw" {
			return Status{
				Name:    "backend.bw",
				Section: "backends",
				OK:      true,
				Detail:  fmt.Sprintf("bw_bin=%s version=%s (backend not selected)", p, ver),
				Tags:    []string{"backend", "bw"},
			}
		}
		return Status{
			Name:    "backend.bw",
			Section: "backends",
			OK:      true,
			Warn:    true,
			Detail:  fmt.Sprintf("bw_bin=%s version=%s", p, ver),
			Fix:     "Run `bw login` and export BW_SESSION to use Bitwarden backend.",
			Tags:    []string{"backend", "bw"},
		}
	}
}

// checkBackendOPAuth checks 1Password authentication without exposing the token.
// It verifies OP_SERVICE_ACCOUNT_TOKEN is set (not empty) and runs
// `op whoami --format=json` to confirm the token actually authenticates —
// token value never in output, only its exit-code-derived verdict.
func checkBackendOPAuth(env llmcontext.Lookup, probe kexec.Probe, runner kexec.CommandRunner) Check {
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

		// check presence only — never expose the token value.
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

		// Resolve the op binary so we can actually verify the token works,
		// rather than just trusting that it is non-empty.
		bin := env("KEYLATCH_OP_BIN")
		if bin == "" {
			var ok bool
			bin, ok, _ = probe.Find(ctx, "op")
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

		// Run `op whoami --format=json` to confirm the token actually
		// authenticates. A revoked/expired OP_SERVICE_ACCOUNT_TOKEN must not
		// report OK here — that was the entire point of this check's name.
		_, _, exitCode, runErr := runner.Run(ctx, bin, []string{"whoami", "--format=json"}, nil)
		if runErr != nil || exitCode != 0 {
			return Status{
				Name:    "backend.op.auth",
				Section: "backends",
				OK:      false,
				Detail:  "OP_SERVICE_ACCOUNT_TOKEN is set but `op whoami` failed — token may be revoked or expired",
				Fix:     "Generate a fresh service account token, or run `op signin` for an interactive session.",
				Tags:    []string{"backend", "op", "auth"},
			}
		}

		return Status{
			Name:    "backend.op.auth",
			Section: "backends",
			OK:      true,
			Detail:  "OP_SERVICE_ACCOUNT_TOKEN is set and verified via `op whoami` (value redacted)",
			Tags:    []string{"backend", "op", "auth"},
		}
	}
}

// checkBackendBWSession checks Bitwarden session state without exposing BW_SESSION.
// BW_SESSION value is never printed.
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

		// check presence only — never expose BW_SESSION value.
		sessionSet := env("BW_SESSION") != ""

		// H5: a cached session (from `keylatch bw unlock`) is an equally
		// valid source of BW_SESSION — checkBackendBWSession must not warn
		// just because the ambient env var itself is unset. StatSession
		// reads only the sidecar metadata file, never the token.
		cacheStatus, cacheErr := bw.StatSession(env)
		cachedValid := cacheErr == nil && cacheStatus.Present && !cacheStatus.Expired

		if !sessionSet && !cachedValid {
			detail := "BW_SESSION not set and no cached session; vault may be locked"
			if cacheErr == nil && cacheStatus.Present && cacheStatus.Expired {
				detail = fmt.Sprintf("cached session expired at %s; vault may be locked",
					cacheStatus.ExpiresAt.Format(time.RFC3339))
			}
			return Status{
				Name:    "backend.bw.session",
				Section: "backends",
				OK:      true,
				Warn:    true,
				Detail:  detail,
				Fix:     "Run `keylatch bw unlock` (or export BW_SESSION yourself — see README §Non-interactive use).",
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

		// do not print BW_SESSION or the cached token; just report binary
		// path and session presence/source.
		_ = bin
		detail := "BW_SESSION is set (value redacted); vault lock state unknown without bw status call"
		if !sessionSet && cachedValid {
			detail = fmt.Sprintf("cached session present (value redacted), expires_at=%s",
				cacheStatus.ExpiresAt.Format(time.RFC3339))
		}
		return Status{
			Name:    "backend.bw.session",
			Section: "backends",
			OK:      true,
			Detail:  detail,
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
