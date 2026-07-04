//go:build darwin && !dev

// Package keychain — release build ACL behaviour.
//
// In release builds (default, no -tags dev), an unsigned keychain ACL is a
// hard error: OpenWithKeyring returns ErrACLMismatch, which surfaces as [FAIL]
// in `keylatch doctor` check A1.
//
// Design rationale: preventing unsigned code from accessing credentials in
// production is a security invariant. A developer who accidentally runs a
// release binary without a signing certificate should see a clear, actionable
// error rather than silent degradation. Dev builds use acl_dev.go which
// retains the previous slog.Warn behaviour.
package keychain

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
)

// checkCodeSigningACL checks whether the current binary is code-signed.
// Release variant: unsigned builds return an error that prevents the keychain
// backend from being used.
func (k *KeychainBackend) checkCodeSigningACL(ctx context.Context) error {
	currentBin, err := os.Executable()
	if err != nil {
		// Cannot determine binary path — fail closed.
		return fmt.Errorf("keychain ACL: could not determine executable path: %w", err)
	}

	identity, signed := k.detectCodeSigningIdentity(ctx, currentBin)
	if !signed || strings.TrimSpace(identity) == "" {
		// Release build: unsigned binary → hard error.
		return fmt.Errorf("%w: binary is not code-signed — keylatch requires a signed binary in production.\n"+
			"  fix: codesign -s <your-team-id> %s\n"+
			"  or:  go build -tags dev ./cmd/keylatch (for development only)",
			backend.ErrACLMismatch, currentBin)
	}
	return nil
}

// OpenWithKeyring extends Open with a mandatory code-signing ACL check.
// In release mode, unsigned binaries cause this function to return an error,
// which surfaces as [FAIL] A1 in `keylatch doctor`.
func OpenWithKeyring(opts Options) (*KeychainBackend, error) {
	b, err := Open(opts)
	if err != nil {
		return nil, err
	}
	// Release: ACL check is mandatory.
	if aclErr := b.checkCodeSigningACL(context.Background()); aclErr != nil {
		return nil, aclErr
	}
	return b, nil
}
