package token

import (
	"errors"
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/paths"
)

// ErrSigningKeyMissing means the gateway has not been initialised.
var ErrSigningKeyMissing = errors.New("token: gateway signing key does not exist (run 'keylatch gateway init')")

// LoadSigningKey returns the gateway signing key, which is stored wrapped by
// the KEK. A raw key file from an older install is wrapped on first use and
// removed. With create set, a missing key is generated.
func LoadSigningKey(env paths.Lookup, k kek.KEK, create bool) ([]byte, error) {
	wrapped := paths.GatewaySigningKeyWrapped(env)
	legacy := paths.GatewaySigningKey(env)

	if raw, err := os.ReadFile(legacy); err == nil { //nolint:gosec // G304: the keylatch gateway key path
		defer clear(raw)
		if len(raw) != kek.SecretSize {
			return nil, fmt.Errorf("token: signing key must be %d bytes", kek.SecretSize)
		}
		if err := kek.WriteSecret(wrapped, k, raw); err != nil {
			return nil, err
		}
		if err := os.Remove(legacy); err != nil {
			return nil, fmt.Errorf("token: remove migrated signing key: %w", err)
		}
		return kek.LoadOrCreateSecret(wrapped, k, false)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("token: read signing key: %w", err)
	}

	key, err := kek.LoadOrCreateSecret(wrapped, k, create)
	if errors.Is(err, kek.ErrSecretMissing) {
		return nil, ErrSigningKeyMissing
	}
	return key, err
}
