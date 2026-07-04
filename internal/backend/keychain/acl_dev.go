//go:build darwin && dev

// Package keychain — dev build ACL behaviour.
//
// In dev builds (go build -tags dev), an unsigned keychain ACL emits a warning
// log but does NOT return an error. This permits development without a signed binary.
//
// Design rationale: release builds must fail-closed on ACL mismatches to
// prevent unsigned code from accessing credentials. Dev builds accept the risk
// because the developer is aware of the unsecured state.
package keychain

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
)

// checkCodeSigningACL checks whether the current binary is code-signed.
// Dev variant: unsigned builds emit slog.Warn but return nil (no error).
// This allows development without a signing certificate.
//
// Called by OpenWithKeyring before the backend is returned to the caller.
func (k *KeychainBackend) checkCodeSigningACL(ctx context.Context) error {
	currentBin, err := os.Executable()
	if err != nil {
		slog.Warn("keychain ACL: could not determine executable path", "error", err)
		return nil
	}

	identity, signed := k.detectCodeSigningIdentity(ctx, currentBin)
	if !signed || strings.TrimSpace(identity) == "" {
		// Dev build: warn but allow.
		slog.Warn("keychain ACL: unsigned binary detected — use a signed build in production",
			"recommendation", "codesign -s <team-id> ./keylatch")
		return nil
	}
	return nil
}

// OpenWithKeyring extends Open with a code-signing ACL check.
// In dev mode this check is advisory; the backend is returned even for unsigned binaries.
func OpenWithKeyring(opts Options) (*KeychainBackend, error) {
	b, err := Open(opts)
	if err != nil {
		return nil, err
	}
	// Dev: ACL check is warn-only.
	if aclErr := b.checkCodeSigningACL(context.Background()); aclErr != nil {
		slog.Warn("keychain ACL check warning", "error", aclErr)
	}
	_ = backend.ErrACLMismatch // referenced to keep import
	return b, nil
}
