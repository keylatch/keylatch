// Package hmac provides HMAC-SHA256 helpers for audit log identity masking.
// All outputs are deterministic: same inputs always produce the same output.
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Of returns HMAC-SHA256(salt, data) truncated to 16 bytes, hex-encoded (32 chars).
// Deterministic; same output for same inputs.
func Of(salt, data []byte) string {
	h := hmac.New(sha256.New, salt)
	h.Write(data)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// ActorHMAC returns a stable 32-char hex identifier for an actor string.
func ActorHMAC(salt []byte, actor string) string {
	return Of(salt, []byte(actor))
}

// AccessorHMAC returns a stable 32-char hex identifier for an accessor string.
func AccessorHMAC(salt []byte, accessor string) string {
	return Of(salt, []byte(accessor))
}

// CommandHMAC returns a stable 32-char hex identifier for a (argv, cwd) pair.
// argv elements are joined with a null byte; cwd is appended after a second null.
func CommandHMAC(salt []byte, argv []string, cwd string) string {
	var sb strings.Builder
	for i, a := range argv {
		if i > 0 {
			sb.WriteByte(0)
		}
		sb.WriteString(a)
	}
	sb.WriteByte(0)
	sb.WriteString(cwd)
	return Of(salt, []byte(sb.String()))
}
