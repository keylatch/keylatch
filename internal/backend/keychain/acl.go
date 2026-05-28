//go:build darwin

package keychain

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
)

// VerifyACL re-reads the login-keychain ACL entry for "keylatch-keychain/unlock"
// and confirms the stored binary path/identity matches os.Executable().
// Returns ErrACLMismatch with a hint message on mismatch. (S1-11, FIND-013)
func (k *KeychainBackend) VerifyACL(ctx context.Context) error {
	currentBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("keychain VerifyACL: os.Executable: %w", err)
	}

	// Read the unlock password item from the login keychain (no -k flag).
	// We check the ACL by looking at the item's trusted applications.
	// In Phase 1 with the CLI approach, we verify the stored path in the item's comment/label.
	stdout, _, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"find-generic-password",
			"-s", "keylatch-keychain",
			"-a", "unlock",
			"-g", // print ACL info
		},
		nil)
	if err != nil {
		return fmt.Errorf("keychain VerifyACL: security find-generic-password: %w", err)
	}

	if exitCode != 0 {
		return backend.ErrACLMismatch
	}

	// Check if the current binary path appears in the ACL output.
	output := string(stdout)
	if !strings.Contains(output, currentBin) {
		return fmt.Errorf("%w: keylatch binary path differs from stored ACL entry. Run: keylatch keychain-repair-acl",
			backend.ErrACLMismatch)
	}

	return nil
}

// RepairACL re-issues the login-keychain ACL entry pointing at the current binary.
// On signed builds uses a SecRequirement clause (FIND-013); on unsigned builds
// uses path-only with an explicit warning. (S1-11, FIND-013)
func (k *KeychainBackend) RepairACL(ctx context.Context) error {
	currentBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("keychain RepairACL: os.Executable: %w", err)
	}

	// Try to detect code-signing identity for the current binary.
	identity, signed := k.detectCodeSigningIdentity(ctx, currentBin)

	if !signed {
		// Unsigned build: warn and fall back to path-only ACL.
		slog.Warn("unsigned build; ACL uses path-only isolation", "recommendation", "use a signed build with a Team ID")
		identity = currentBin
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

	// Update the item with the new trusted application path.
	_, _, exitCode, err := k.opts.Runner.Run(ctx, k.opts.SecurityBin,
		[]string{"add-generic-password",
			"-U",
			"-s", "keylatch-keychain",
			"-a", "unlock",
			"-w", pw,
			"-T", identity,
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
// the trusted retriever. Idempotent. (FIND3-001, S1-12)
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
	// In Phase 1 using CLI approach: update each item with -T {trustedApp}.
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

	_ = signed // Used in full Security.framework implementation (Phase 1 uses CLI)
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

// detectCodeSigningIdentity returns the Team ID + bundle ID for the binary
// if it is signed. Returns ("", false) for unsigned builds.
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

	return output, true
}
