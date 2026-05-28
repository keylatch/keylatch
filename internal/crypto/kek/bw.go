package kek

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// bwKEK implements KEK using the Bitwarden CLI (bw).
type bwKEK struct {
	itemID      string
	fieldName   string
	runner      func(args ...string) ([]byte, error)
	wrappingKey []byte
}

// BWKEK returns a KEK that reads a field from a Bitwarden item.
// Requires the BW_SESSION environment variable to be set.
func BWKEK(itemID, fieldName string) (KEK, error) {
	runner := func(args ...string) ([]byte, error) {
		out, err := exec.Command("bw", args...).Output() //nolint:gosec // G204: "bw" is the Bitwarden CLI binary; it is a fixed string, not user input
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	return bwKEKWithRunner(itemID, fieldName, runner)
}

func bwKEKWithRunner(itemID, fieldName string, runner func(...string) ([]byte, error)) (KEK, error) {
	if os.Getenv("BW_SESSION") == "" {
		return nil, fmt.Errorf("%w: BW_SESSION not set", ErrKEKUnavailable)
	}

	out, err := runner("get", "item", itemID)
	if err != nil {
		return nil, fmt.Errorf("%w: bw get item failed: %v", ErrKEKUnavailable, err)
	}

	// Parse the JSON item and extract the field value.
	hexVal, err := extractBWField(out, fieldName)
	if err != nil {
		return nil, fmt.Errorf("%w: extract field %q from item %q: %v", ErrKEKUnavailable, fieldName, itemID, err)
	}

	key, err := parseHexKey(strings.TrimSpace(hexVal))
	if err != nil {
		return nil, fmt.Errorf("%w: bw field %q in item %q: %v", ErrKEKUnavailable, fieldName, itemID, err)
	}

	return &bwKEK{
		itemID:      itemID,
		fieldName:   fieldName,
		runner:      runner,
		wrappingKey: key,
	}, nil
}

// extractBWField parses the Bitwarden item JSON and extracts the named field.
func extractBWField(data []byte, fieldName string) (string, error) {
	var item struct {
		Fields []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(data, &item); err != nil {
		return "", fmt.Errorf("parse bw item JSON: %w", err)
	}
	for _, f := range item.Fields {
		if f.Name == fieldName {
			return f.Value, nil
		}
	}
	return "", fmt.Errorf("field %q not found in item", fieldName)
}

// Wrap encrypts dek using XChaCha20-Poly1305 keyed by the Bitwarden-retrieved key.
func (k *bwKEK) Wrap(dek []byte) ([]byte, error) {
	ct, nonce, err := envelope.SealXChaCha20(k.wrappingKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("kek: bw wrap: %w", err)
	}
	result := make([]byte, len(nonce)+len(ct))
	copy(result, nonce)
	copy(result[len(nonce):], ct)
	return result, nil
}

// Unwrap decrypts a blob produced by Wrap.
func (k *bwKEK) Unwrap(wrapped []byte) ([]byte, error) {
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

// ID returns the Bitwarden item/field reference.
func (k *bwKEK) ID() string { return fmt.Sprintf("bw://%s/%s", k.itemID, k.fieldName) }

// Type returns the KEK provider type.
func (k *bwKEK) Type() string { return "bw" }
