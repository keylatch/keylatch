// Package aad marshals vault.AADBinding to its RFC 8785 canonical JSON form.
// The canonical bytes are used as AEAD associated data, binding the ciphertext
// to its path, version, key term, backend, and algorithm at encryption time.
//
// Output is deterministic and byte-stable across Go versions.
package aad

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/jcs"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// Marshal converts b to its JCS canonical JSON representation.
//
// The output for the fixture binding is byte-for-byte:
//
//	{"algorithm":"xchacha20-poly1305","backend_id":"file:0x4a","created_at":"2026-05-11T12:00:00Z","key_term":2,"namespace":"default","path":"ai/openrouter/api_key","schema_version":1,"version":3}
func Marshal(b vmeta.AADBinding) ([]byte, error) {
	m := map[string]any{
		"schema_version": b.SchemaVersion,
		"namespace":      b.Namespace,
		"path":           b.Path,
		"version":        b.Version,
		"key_term":       b.KeyTerm,
		"backend_id":     b.BackendID,
		"created_at":     b.CreatedAt.UTC().Format(time.RFC3339),
		"algorithm":      b.Algorithm,
	}

	out, err := jcs.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("aad: marshal: %w", err)
	}
	return out, nil
}

// Unmarshal deserializes canonical JSON bytes produced by Marshal back into
// a vmeta.AADBinding. Used for round-trip tests only — not on the critical path.
func Unmarshal(data []byte) (vmeta.AADBinding, error) {
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		return vmeta.AADBinding{}, fmt.Errorf("aad: unmarshal: %w", err)
	}

	var b vmeta.AADBinding

	if v, ok := m["schema_version"].(json.Number); ok {
		n, _ := v.Int64()
		b.SchemaVersion = int(n)
	}
	if v, ok := m["namespace"].(string); ok {
		b.Namespace = v
	}
	if v, ok := m["path"].(string); ok {
		b.Path = v
	}
	if v, ok := m["version"].(json.Number); ok {
		n, _ := v.Int64()
		b.Version = int(n)
	}
	if v, ok := m["key_term"].(json.Number); ok {
		n, _ := v.Int64()
		b.KeyTerm = int(n)
	}
	if v, ok := m["backend_id"].(string); ok {
		b.BackendID = v
	}
	if v, ok := m["created_at"].(string); ok {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return vmeta.AADBinding{}, fmt.Errorf("aad: parse created_at: %w", err)
		}
		b.CreatedAt = t
	}
	if v, ok := m["algorithm"].(string); ok {
		b.Algorithm = v
	}

	return b, nil
}
