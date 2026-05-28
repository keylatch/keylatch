// Package challenge implements ephemeral challenge creation and verification
// for the Phase 11 Root of Trust approval flow.
//
// Security invariants:
//   - Challenges are deterministically encoded (JCS-style sorted keys) so the
//     signer and verifier produce identical byte sequences.
//   - Expired challenges always return ErrChallengeExpired regardless of signature validity.
//   - Supported algorithms: Ed25519, ECDSA P-256, RSA-PSS SHA-256.
package challenge

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// Bind controls what context is bound into the challenge.
type Bind string

const (
	// BindNone applies no additional binding beyond actor + capability.
	BindNone Bind = "none"
	// BindCommand binds the challenge to a specific command hash.
	BindCommand Bind = "command"
	// BindCWD binds the challenge to the current working directory hash.
	BindCWD Bind = "cwd"
	// BindFull binds both command and CWD.
	BindFull Bind = "full"
)

// Challenge is an ephemeral approval challenge issued for a specific actor and capability.
type Challenge struct {
	// Actor is the identity requesting approval.
	Actor string `json:"actor"`
	// Capability is the operation being approved.
	Capability string `json:"capability"`
	// CommandHash is a SHA-256 hex digest of the command being approved (optional).
	CommandHash string `json:"command_hash,omitempty"`
	// CwdHash is a SHA-256 hex digest of the working directory (optional).
	CwdHash string `json:"cwd_hash,omitempty"`
	// Exp is the expiry time of this challenge.
	Exp time.Time `json:"exp"`
	// Bind controls what fields participate in signature binding.
	Bind Bind `json:"bind,omitempty"`
	// Nonce is a random 16-byte hex string to prevent replay.
	Nonce string `json:"nonce"`
}

// ErrChallengeExpired is returned when a challenge has passed its Exp time.
var ErrChallengeExpired = errors.New("challenge: expired")

// ErrSignatureInvalid is returned when signature verification fails.
var ErrSignatureInvalid = errors.New("challenge: signature invalid")

// ErrUnsupportedKeyType is returned when the public key algorithm is not supported.
var ErrUnsupportedKeyType = errors.New("challenge: unsupported key type")

// New creates a new Challenge for actor with capability, expiring after ttl.
func New(actor, capability string, ttl time.Duration) Challenge {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	nonceHex := fmt.Sprintf("%x", nonce)
	return Challenge{
		Actor:      actor,
		Capability: capability,
		Exp:        time.Now().UTC().Add(ttl),
		Bind:       BindNone,
		Nonce:      nonceHex,
	}
}

// Bytes produces a deterministic, RFC 8785 JCS-style canonical encoding of c.
// Fields are serialized with sorted keys and no whitespace.
// This MUST produce identical output given identical Challenge values.
func (c Challenge) Bytes() []byte {
	// Build an ordered map to ensure deterministic key ordering.
	m := map[string]any{
		"actor":      c.Actor,
		"bind":       string(c.Bind),
		"capability": c.Capability,
		"exp":        c.Exp.UTC().Format(time.RFC3339Nano),
		"nonce":      c.Nonce,
	}
	if c.CommandHash != "" {
		m["command_hash"] = c.CommandHash
	}
	if c.CwdHash != "" {
		m["cwd_hash"] = c.CwdHash
	}

	// Sort keys and build the canonical JSON manually to ensure determinism.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(m[k])
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// Verify checks that sig is a valid signature over c by pub.
// Returns ErrChallengeExpired if c has expired.
// Returns ErrSignatureInvalid for any cryptographic failure.
// Returns ErrUnsupportedKeyType for unrecognised key types.
//
// Supported algorithms:
//   - Ed25519: raw 64-byte signature
//   - ECDSA P-256: DER-encoded signature (two ASN.1 integers r, s)
//   - RSA-PSS SHA-256: PKCS#8 PSS signature
func Verify(c Challenge, sig []byte, pub crypto.PublicKey) error {
	if time.Now().UTC().After(c.Exp) {
		return ErrChallengeExpired
	}

	msg := c.Bytes()

	switch key := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(key, msg, sig) {
			return ErrSignatureInvalid
		}
		return nil

	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return fmt.Errorf("%w: ECDSA key must be P-256", ErrUnsupportedKeyType)
		}
		digest := sha256.Sum256(msg)
		r, s := new(big.Int), new(big.Int)
		if !parseDERSig(sig, r, s) {
			return ErrSignatureInvalid
		}
		if !ecdsa.Verify(key, digest[:], r, s) {
			return ErrSignatureInvalid
		}
		return nil

	case *rsa.PublicKey:
		digest := sha256.Sum256(msg)
		opts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		}
		if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], sig, opts); err != nil {
			return ErrSignatureInvalid
		}
		return nil

	default:
		return ErrUnsupportedKeyType
	}
}

// parseDERSig parses a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }).
// Returns false on parse failure.
func parseDERSig(der []byte, r, s *big.Int) bool {
	if len(der) < 2 || der[0] != 0x30 {
		return false
	}
	// Total length.
	seqLen := int(der[1])
	if len(der) < 2+seqLen {
		return false
	}
	body := der[2 : 2+seqLen]

	// Parse r.
	if len(body) < 2 || body[0] != 0x02 {
		return false
	}
	rLen := int(body[1])
	if len(body) < 2+rLen {
		return false
	}
	r.SetBytes(body[2 : 2+rLen])
	body = body[2+rLen:]

	// Parse s.
	if len(body) < 2 || body[0] != 0x02 {
		return false
	}
	sLen := int(body[1])
	if len(body) < 2+sLen {
		return false
	}
	s.SetBytes(body[2 : 2+sLen])
	return true
}
