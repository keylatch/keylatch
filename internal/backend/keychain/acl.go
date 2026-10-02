//go:build darwin

package keychain

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
)

// VerifyACL performs a real, harmless read of the login-keychain unlock item
// via the same code path Get/Set/Delete use (readUnlockPassword) and reports
// whether the ACL actually trusts the current binary.
//
// The previous implementation grepped `security find-generic-password -g`
// output for the current binary's path — but `-g` never prints the ACL's
// trusted-application list (that information isn't exposed via the `find-
// generic-password` CLI at all), so that check could never pass on real
// macOS and produced a permanent false-positive "ACL mismatch" warning.
//
// A real read is the only reliable signal: macOS enforces the ACL at read
// time, so if the current binary isn't in the trusted-application list, the
// read itself fails with errSecAuthFailed / errSecInteractionNotAllowed —
// which readUnlockPassword already classifies as backend.ErrACLMismatch. A
// successful read means the ACL is fine.
func (k *KeychainBackend) VerifyACL(ctx context.Context) error {
	if _, err := k.readUnlockPassword(ctx); err != nil {
		if errors.Is(err, backend.ErrACLMismatch) {
			return err
		}
		// Any other failure (e.g. the unlock item genuinely does not exist
		// yet — exit 44) is not an ACL problem; surface it as-is rather than
		// misreporting it as an ACL mismatch.
		return fmt.Errorf("keychain VerifyACL: %w", err)
	}
	return nil
}

// RepairACL re-issues the login-keychain ACL entry pointing at the current
// binary. `security add-generic-password -T` always expects a filesystem
// PATH to the trusted application (see `man security`) — it does not accept
// a code-signing identity, Team ID, or SecRequirement text, on either signed
// or unsigned builds. The `-T` value is therefore always currentBin.
// detectCodeSigningIdentity is only used to decide whether to log a warning
// about the binary lacking a stable signing identity (unsigned or
// ad-hoc-signed, e.g. the default for `go build` on Apple Silicon).
//
// KNOWN GAP (review Finding-003, not fixed here): unlike Get/Set/Delete
// (keychain.go), RepairACL does not call acquireFlock, so it is not
// serialized against concurrent Init/ForceReinit/RepairACL calls across
// processes. See init.go's matching note for the concrete race scenario.
// Left as a follow-up: wrap this in acquireFlock(k.opts.LockPath).
func (k *KeychainBackend) RepairACL(ctx context.Context) error {
	currentBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("keychain RepairACL: os.Executable: %w", err)
	}

	identity, signed := k.detectCodeSigningIdentity(ctx, currentBin)
	if !signed {
		slog.Warn("binary has no stable code-signing identity; ACL uses path-only isolation",
			"recommendation", "use a signed build with a Team ID")
	} else {
		slog.Debug("code-signing identity detected", "identity", identity)
	}

	// Re-issue the unlock password item with the updated ACL.
	// Read existing password first so we don't change it.
	pwOut, _, pwExit, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"find-generic-password", "-s", "keylatch-keychain", "-a", "unlock", "-w"},
		nil)
	if err != nil {
		return fmt.Errorf("keychain RepairACL: read existing password: %w", err)
	}
	if pwExit != 0 {
		return fmt.Errorf("keychain RepairACL: no existing unlock password found (run keychain-init first)")
	}

	pw := strings.TrimRight(string(pwOut), "\n")

	// Update the item with the trusted application path. Always currentBin —
	// see the doc comment above for why this is never the codesign identity.
	_, _, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"add-generic-password",
			"-U",
			"-s", "keylatch-keychain",
			"-a", "unlock",
			"-w", pw,
			"-T", currentBin,
		},
		nil)
	if err != nil {
		return fmt.Errorf("keychain RepairACL: add-generic-password: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("keychain RepairACL: security exited %d", exitCode)
	}

	return nil
}

// RepairItemACLs walks every keylatch-* item in the custom keychain and
// re-issues a per-item SecAccess ACL naming only the Keylatch binary as
// the trusted retriever. Idempotent.
func (k *KeychainBackend) RepairItemACLs(ctx context.Context) error {
	// Read the manifest to enumerate all items — no bulk value reads.
	manifest, err := k.loadManifest(ctx)
	if err != nil {
		return fmt.Errorf("keychain RepairItemACLs: loadManifest: %w", err)
	}

	currentBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("keychain RepairItemACLs: os.Executable: %w", err)
	}

	_, signed := k.detectCodeSigningIdentity(ctx, currentBin)
	trustedApp := currentBin

	// For each item in the manifest, re-issue the per-item ACL.
	// Using the CLI approach: update each item with -T {trustedApp}.
	for _, row := range manifest.Items {
		for _, field := range row.Fields {
			if err := k.repairItemACL(ctx, row.Connection, field, trustedApp); err != nil {
				return fmt.Errorf("keychain RepairItemACLs: repair %s/%s: %w",
					row.Connection, field, err)
			}
		}
	}

	// Also repair the manifest item ACL.
	if err := k.repairItemACL(ctx, "_manifest", "manifest", trustedApp); err != nil {
		// Not fatal on first run (manifest may not exist yet).
		_ = err
	}

	_ = signed // Used in full Security.framework implementation (current approach uses CLI)
	return nil
}

// repairItemACL re-issues the ACL for a single keychain item.
func (k *KeychainBackend) repairItemACL(ctx context.Context, conn, field, trustedApp string) error {
	// Read the current value.
	valOut, _, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"find-generic-password",
			"-s", "keylatch-" + conn,
			"-a", field,
			"-w",
			"-k", k.opts.KeychainPath,
		},
		nil)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return nil // item may not exist; skip
	}

	val := strings.TrimRight(string(valOut), "\n")

	// Re-write with -T {trustedApp} to update the ACL.
	_, _, _, err = k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"add-generic-password",
			"-U",
			"-s", "keylatch-" + conn,
			"-a", field,
			"-w", val,
			"-T", trustedApp,
			"-k", k.opts.KeychainPath,
		},
		nil)
	return err
}

// detectCodeSigningIdentity reports whether binPath has a real, stable
// code-signing identity (a Team ID) and returns the raw codesign dump for
// diagnostic logging. Returns ("", false) for unsigned builds AND for
// ad-hoc-signed builds (Signature=adhoc / TeamIdentifier=not set) — the
// default codesign applied by the linker on Apple Silicon `go build`. An
// ad-hoc signature has no Team ID and changes on every rebuild, so it is not
// a real identity worth trusting for ACL purposes even though `codesign -dv`
// exits 0 for it (C4: treating "codesign didn't fail" as "signed" caused
// RepairACL to pass the raw multi-line dump to `-T`, which only accepts a
// filesystem path — see RepairACL's doc comment).
func (k *KeychainBackend) detectCodeSigningIdentity(ctx context.Context, binPath string) (string, bool) {
	stdout, _, exitCode, err := k.opts.Runner.Run(ctx, "/usr/bin/codesign",
		[]string{"-dv", "--requirement", "-", binPath},
		nil)
	if err != nil || exitCode != 0 {
		return "", false
	}

	output := strings.TrimSpace(string(stdout))
	if output == "" || strings.Contains(output, "not signed") {
		return "", false
	}
	if strings.Contains(output, "Signature=adhoc") || strings.Contains(output, "TeamIdentifier=not set") {
		return "", false
	}

	return output, true
}
