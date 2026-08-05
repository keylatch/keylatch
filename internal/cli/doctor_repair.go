package cli

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/backend/keychain"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// repairableChecks lists the doctor check Names with a safe, idempotent
// automated repair (H1). Deliberately narrow: many failure classes (missing
// bootstrap, wrong backend selected, an external CLI not installed) have no
// safe automated fix — "repairing" them would mean guessing user intent
// (which backend? which credentials?). Only checks whose repair action is
// already implemented elsewhere as a read-before-write, non-destructive
// operation are included here.
var repairableChecks = map[string]bool{
	"acl.keychain_unlock": true,
}

// runDoctorRepair implements `keylatch doctor --repair` (H1).
//
// docs/cli-reference.md documented --repair/--yes as generally repairing
// "failed/warned checks", and the flags were registered on the command, but
// RunE never read them — doctor --repair was a fully silent no-op. This
// implements exactly the repair actions already available and safe to run
// unattended (currently: keychain ACL, via the existing RepairACL/
// RepairItemACLs methods) and reports "no automated repair" with the
// check's existing Fix hint for everything else, rather than promising a
// broader repair surface the codebase doesn't actually have yet.
//
// yes=true skips the interactive per-check confirmation prompt.
// Returns the report to display: if anything was repaired, doctor is
// re-run so the caller sees the post-repair state; otherwise the original
// report is returned unchanged.
func runDoctorRepair(ctx context.Context, stdout, stderr io.Writer, report doctor.Report, env llmcontext.Lookup, yes bool) doctor.Report {
	var anyRepaired bool

	for _, s := range report.Checks {
		if s.OK && !s.Warn {
			continue // healthy check — nothing to repair
		}
		if !repairableChecks[s.Name] {
			if s.Fix != "" {
				fmt.Fprintf(stdout, "  [no automated repair] %s: run: %s\n", s.Name, s.Fix)
			} else {
				fmt.Fprintf(stdout, "  [no automated repair] %s\n", s.Name)
			}
			continue
		}

		// review Finding-004: the ACL check itself only gates on whether a
		// keychain-db file happens to exist on disk, not on whether keychain
		// is the actively selected backend (a leftover file from before an
		// H2 backend switch would otherwise still trigger a repair). Skip
		// the repair — not just the check — when keychain isn't in active use.
		if s.Name == "acl.keychain_unlock" && !keychainACLRepairApplies(env) {
			fmt.Fprintf(stdout, "  [no automated repair] %s: stale keychain file detected, unrelated to your active backend\n", s.Name)
			continue
		}

		if !yes {
			fmt.Fprintf(stdout, "Repair %s (re-issue the keychain ACL for this binary)? [y/N]: ", s.Name)
			ans := strings.ToLower(strings.TrimSpace(readLine()))
			if ans != "y" && ans != "yes" {
				fmt.Fprintf(stdout, "  skipped %s (not confirmed — pass --yes to skip this prompt)\n", s.Name)
				continue
			}
		}

		if err := repairKeychainACL(ctx, env); err != nil {
			fmt.Fprintf(stderr, "  repair %s failed: %v\n", s.Name, err)
			continue
		}
		fmt.Fprintf(stdout, "  repaired %s\n", s.Name)
		anyRepaired = true
	}

	if !anyRepaired {
		return report
	}

	fresh, err := doctor.Run(ctx, doctor.Options{Verbose: true, Env: env})
	if err != nil {
		fmt.Fprintf(stderr, "  doctor: re-check after repair failed: %v\n", err)
		return report
	}
	return fresh
}

// keychainACLRepairApplies reports whether the keychain-ACL repair is
// applicable: keychain must be the actively selected backend (normalized
// through backend.CanonicalName so aliases match), and the keychain backend
// only exists on darwin (review Finding-004).
func keychainACLRepairApplies(env llmcontext.Lookup) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	cfg, err := config.Load(paths.Config(env))
	if err != nil {
		cfg = config.Default()
	}
	canonical, ok := backend.CanonicalName(cfg.Backend)
	return ok && canonical == "keychain"
}

// repairKeychainACL re-issues the login-keychain ACL entry and every
// per-item ACL for the currently selected keychain backend. Both operations
// are idempotent (see their doc comments in internal/backend/keychain/acl.go)
// — safe to run without confirmation once the user has agreed to --repair.
func repairKeychainACL(ctx context.Context, env llmcontext.Lookup) error {
	cfg, err := config.Load(paths.Config(env))
	if err != nil {
		cfg = config.Default()
	}
	cfg.Backend = "keychain"
	dispatch.ClearCached()

	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return fmt.Errorf("open keychain backend: %w", err)
	}
	defer func() { _ = b.Close() }()

	kb, ok := b.(*keychain.KeychainBackend)
	if !ok {
		return fmt.Errorf("backend is not a KeychainBackend")
	}
	if err := kb.RepairACL(ctx); err != nil {
		return fmt.Errorf("RepairACL: %w", err)
	}
	if err := kb.RepairItemACLs(ctx); err != nil {
		return fmt.Errorf("RepairItemACLs: %w", err)
	}
	return nil
}
