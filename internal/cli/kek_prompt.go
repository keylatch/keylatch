package cli

import (
	"crypto/subtle"
	"errors"

	"github.com/keylatch/keylatch/internal/backend/file"
)

// minVaultPassphrase is the shortest passphrase accepted for a new vault key.
const minVaultPassphrase = 10

func init() {
	file.PassphraseSource = askVaultPassphrase
}

// askVaultPassphrase asks for the passphrase of a passphrase-wrapped keyring.
// It reads from a terminal only.
func askVaultPassphrase() ([]byte, error) {
	if !interactiveStdin() {
		return nil, file.ErrPassphraseNeedsTerminal
	}
	pass, err := promptHidden("Vault passphrase")
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, errors.New("the vault passphrase is empty")
	}
	return pass, nil
}

// chooseVaultPassphrase asks twice for a new passphrase on the terminal.
func chooseVaultPassphrase() ([]byte, error) {
	if !interactiveStdin() {
		return nil, file.ErrPassphraseNeedsTerminal
	}
	pass, err := promptHidden("Choose a vault passphrase")
	if err != nil {
		return nil, err
	}
	if len(pass) < minVaultPassphrase {
		clear(pass)
		return nil, NewUsageError("the vault passphrase must be at least %d characters", minVaultPassphrase)
	}
	again, err := promptHidden("Repeat the vault passphrase")
	if err != nil {
		clear(pass)
		return nil, err
	}
	defer clear(again)
	if subtle.ConstantTimeCompare(pass, again) != 1 {
		clear(pass)
		return nil, NewUsageError("the passphrases do not match")
	}
	return pass, nil
}

// vaultPassphraseOption offers choosing a passphrase only when a human is at a
// terminal; without one it is nil and bootstrap never falls back to it.
func vaultPassphraseOption() func() ([]byte, error) {
	if interactiveStdin() {
		return chooseVaultPassphrase
	}
	return nil
}

// insecureFileKEKAllowed reports whether the operator's own config file lets
// bootstrap keep the vault identity in a plaintext file. Only the default
// config file counts, and only when it is owned by the current user and not
// writable by anyone else; no flag or environment variable can set it.
var insecureFileKEKAllowed = func() bool {
	cfg, err := operatorConfig()
	return err == nil && cfg.AllowInsecureFileKEK
}
