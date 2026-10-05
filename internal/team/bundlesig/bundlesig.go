// Package bundlesig signs and verifies team bundles (invites, org policy,
// internal registry) with Ed25519 over a domain-separated message.
//
// Signatures are encoded as "ed25519:<base64>". Bundles written before
// signatures were keyed carry a bare hex SHA-256 digest instead; anyone can
// recompute that digest, so it is reported as ErrLegacySignature and never
// accepted.
package bundlesig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const sigPrefix = "ed25519:"

var (
	ErrUnsigned         = errors.New("bundle is not signed")
	ErrLegacySignature  = errors.New("bundle carries an unkeyed legacy SHA-256 signature")
	ErrInvalidSignature = errors.New("bundle signature does not verify against the trusted key")
	ErrNoTrustedKey     = errors.New("no trusted Ed25519 public key given")
)

var legacyDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Message builds the signed message: the domain followed by each field,
// every part length-prefixed so field boundaries cannot be shifted.
func Message(domain string, fields ...string) []byte {
	n := 4 + len(domain)
	for _, f := range fields {
		n += 4 + len(f)
	}
	msg := make([]byte, 0, n)
	for _, part := range append([]string{domain}, fields...) {
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(part))) //nolint:gosec // G115: bundle fields are far below 4 GiB
		msg = append(msg, part...)
	}
	return msg
}

// Sign returns the encoded signature of msg.
func Sign(priv ed25519.PrivateKey, msg []byte) string {
	return sigPrefix + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
}

// Verify checks an encoded signature of msg against pub.
func Verify(pub ed25519.PublicKey, msg []byte, sig string) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrNoTrustedKey
	}
	switch {
	case sig == "":
		return ErrUnsigned
	case legacyDigest.MatchString(sig):
		return ErrLegacySignature
	case !strings.HasPrefix(sig, sigPrefix):
		return ErrInvalidSignature
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sig, sigPrefix))
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, raw) {
		return ErrInvalidSignature
	}
	return nil
}

// EncodePublicKey returns the base64 form ParsePublicKey accepts.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrNoTrustedKey
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key: want base64 of %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// CreateKeyFile generates a key pair and writes the private seed to path
// with mode 0600. It fails if path already exists.
func CreateKeyFile(path string) (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path is a keylatch-owned key location
	if err != nil {
		return nil, fmt.Errorf("create signing key %q: %w", path, err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write signing key %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("write signing key %q: %w", path, err)
	}
	return priv, nil
}

// LoadKeyFile reads a private key written by CreateKeyFile.
func LoadKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a keylatch-owned key location
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key %q is malformed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
