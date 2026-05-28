package kek

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// opKEK implements KEK using 1Password CLI (op).
type opKEK struct {
	vaultName   string
	itemTitle   string
	fieldName   string
	runner      func(args ...string) ([]byte, error)
	wrappingKey []byte
}

// OPKEK returns a KEK that reads a 32-byte hex-encoded field from 1Password.
// The field value is used as the wrapping key.
func OPKEK(vaultName, itemTitle, fieldName string) (KEK, error) {
	runner := func(args ...string) ([]byte, error) {
		out, err := exec.Command("op", args...).Output() //nolint:gosec // G204: "op" is the 1Password CLI binary; it is a fixed string, not user input
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	return opKEKWithRunner(vaultName, itemTitle, fieldName, runner)
}

func opKEKWithRunner(vaultName, itemTitle, fieldName string, runner func(...string) ([]byte, error)) (KEK, error) {
	ref := fmt.Sprintf("op://%s/%s/%s", vaultName, itemTitle, fieldName)
	out, err := runner("read", ref)
	if err != nil {
		return nil, fmt.Errorf("%w: op read failed: %v", ErrKEKUnavailable, err)
	}

	key, err := parseHexKey(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, fmt.Errorf("%w: op field %q: %v", ErrKEKUnavailable, ref, err)
	}

	return &opKEK{
		vaultName:   vaultName,
		itemTitle:   itemTitle,
		fieldName:   fieldName,
		runner:      runner,
		wrappingKey: key,
	}, nil
}

// Wrap encrypts dek using XChaCha20-Poly1305 keyed by the 1Password-retrieved key.
func (k *opKEK) Wrap(dek []byte) ([]byte, error) {
	ct, nonce, err := envelope.SealXChaCha20(k.wrappingKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("kek: op wrap: %w", err)
	}
	result := make([]byte, len(nonce)+len(ct))
	copy(result, nonce)
	copy(result[len(nonce):], ct)
	return result, nil
}

// Unwrap decrypts a blob produced by Wrap.
func (k *opKEK) Unwrap(wrapped []byte) ([]byte, error) {
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

// ID returns the 1Password item reference.
func (k *opKEK) ID() string {
	return fmt.Sprintf("op://%s/%s/%s", k.vaultName, k.itemTitle, k.fieldName)
}

// Type returns the KEK provider type.
func (k *opKEK) Type() string { return "op" }

// parseHexKey parses a 64-character hex string into a 32-byte slice.
func parseHexKey(hexStr string) ([]byte, error) {
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("expected 64 hex chars, got %d", len(hexStr))
	}
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var b byte
		if _, err := fmt.Sscanf(hexStr[i*2:i*2+2], "%02x", &b); err != nil {
			return nil, fmt.Errorf("invalid hex at position %d: %v", i*2, err)
		}
		key[i] = b
	}
	return key, nil
}
