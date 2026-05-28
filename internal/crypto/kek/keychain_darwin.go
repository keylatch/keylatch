//go:build darwin

package kek

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// keychainKEK implements KEK using macOS Keychain generic-password items.
type keychainKEK struct {
	itemName    string
	wrappingKey []byte
}

// CommandRunner executes an OS command and returns its output.
// Replaceable in tests via MockRunner.
type CommandRunner func(name string, args ...string) ([]byte, error)

// defaultRunner runs the real command via exec.Command.
var defaultRunner CommandRunner = func(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).Output() //nolint:gosec // G204: name is either "security" (macOS system binary) or a test mock; not user input
	if err != nil {
		return nil, err
	}
	return out, nil
}

// KeychainKEK retrieves a 32-byte generic-password item from the macOS Keychain
// and returns a KEK backed by that material.
//
// The Keychain item must have been created by `keylatch backend init --kek=keychain`.
// This function only reads the item; it does not create or update it.
func KeychainKEK(itemName string) (KEK, error) {
	return keychainKEKWithRunner(itemName, defaultRunner)
}

func keychainKEKWithRunner(itemName string, runner CommandRunner) (KEK, error) {
	out, err := runner("security", "find-generic-password", "-s", itemName, "-w")
	if err != nil {
		return nil, fmt.Errorf("%w: keychain item %q not found: %v", ErrKEKUnavailable, itemName, err)
	}

	hexKey := strings.TrimSpace(string(out))
	if len(hexKey) < 64 {
		return nil, fmt.Errorf("%w: keychain item %q has unexpected length", ErrKEKUnavailable, itemName)
	}

	// Parse the hex-encoded 32-byte key.
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var b byte
		if _, err := fmt.Sscanf(hexKey[i*2:i*2+2], "%02x", &b); err != nil {
			return nil, fmt.Errorf("%w: keychain item %q is not hex-encoded: %v", ErrKEKUnavailable, itemName, err)
		}
		key[i] = b
	}

	return &keychainKEK{itemName: itemName, wrappingKey: key}, nil
}

// Wrap encrypts dek using XChaCha20-Poly1305 keyed by the Keychain-retrieved key.
func (k *keychainKEK) Wrap(dek []byte) ([]byte, error) {
	ct, nonce, err := envelope.SealXChaCha20(k.wrappingKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("kek: keychain wrap: %w", err)
	}
	result := make([]byte, len(nonce)+len(ct))
	copy(result, nonce)
	copy(result[len(nonce):], ct)
	return result, nil
}

// Unwrap decrypts a blob produced by Wrap.
func (k *keychainKEK) Unwrap(wrapped []byte) ([]byte, error) {
	const nonceLen = 24
	if len(wrapped) < nonceLen {
		return nil, ErrKEKUnavailable
	}
	nonce := wrapped[:nonceLen]
	ct := wrapped[nonceLen:]

	dek, err := envelope.Open(envelope.XChaCha20Poly1305, k.wrappingKey, ct, nonce, nil)
	if err != nil {
		return nil, ErrKEKUnavailable
	}
	return dek, nil
}

// ID returns the Keychain item name.
func (k *keychainKEK) ID() string { return k.itemName }

// Type returns the KEK provider type.
func (k *keychainKEK) Type() string { return "keychain" }
