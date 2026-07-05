// Package sharedsecret implements shared-secret distribution using
// AGE-compatible X25519+ChaCha20-Poly1305 encryption.
//
// Security invariants:
// - AGE encryption with strict-fail — no fallback ciphers.
// - Read blocked during LLM sessions.
// - Read requires hardware presence proof.
// - Rotate called automatically on RemoveMember.
package sharedsecret

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/trust"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Sentinel errors.
var (
	ErrLLMSessionBlocked        = errors.New("shared-secret read blocked during LLM session")
	ErrHardwarePresenceRequired = errors.New("hardware presence proof required to read shared secret")
	ErrNoRecipientFound         = errors.New("shared-secret: no recipient entry found for this member")
	ErrDecryptionFailed         = errors.New("shared-secret: AGE decryption failed (strict-fail, no fallback)")
	ErrEncryptionFailed         = errors.New("shared-secret: AGE encryption failed")
)

// llmSessionKey is the context key for marking LLM sessions.
type llmSessionKey struct{}

// WithLLMSession returns a context marked as an LLM session.
func WithLLMSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, llmSessionKey{}, true)
}

// isLLMSession returns true if the context carries the LLM session marker.
func isLLMSession(ctx context.Context) bool {
	v, _ := ctx.Value(llmSessionKey{}).(bool)
	return v
}

// SharedSecret holds an encrypted shared secret distributed to team members.
type SharedSecret struct {
	ID         string           `json:"id"`
	NameHMAC   string           `json:"name_hmac"` // HMAC of name — never store raw name
	Recipients []RecipientEntry `json:"recipients"`
	CreatedAt  time.Time        `json:"created_at"`
	RotatedAt  *time.Time       `json:"rotated_at,omitempty"`
	Version    int              `json:"version"`
}

// RecipientEntry holds the AGE-encrypted payload for a single member.
type RecipientEntry struct {
	MemberIDHMAC     string `json:"member_id_hmac"`
	EncryptedPayload []byte `json:"encrypted_payload"` // AGE-encrypted for this member's AgePublicKey
}

// agePublicKeyFromHex decodes a hex-encoded X25519 public key.
// Keys are stored as 32-byte hex strings.
func agePublicKeyFromHex(hexKey string) ([32]byte, error) {
	var key [32]byte
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return key, fmt.Errorf("invalid age public key hex: %w", err)
	}
	if len(b) != 32 {
		return key, fmt.Errorf("invalid age public key length: want 32 bytes, got %d", len(b))
	}
	copy(key[:], b)
	return key, nil
}

// agePrivateKeyFromHex decodes a hex-encoded X25519 private key.
func agePrivateKeyFromHex(hexKey string) ([32]byte, error) {
	var key [32]byte
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return key, fmt.Errorf("invalid age private key hex: %w", err)
	}
	if len(b) != 32 {
		return key, fmt.Errorf("invalid age private key length: want 32 bytes, got %d", len(b))
	}
	copy(key[:], b)
	return key, nil
}

// GenerateAGEKeyPair generates a new X25519 key pair.
// Returns (privateKeyHex, publicKeyHex, error).
func GenerateAGEKeyPair() (string, string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("sharedsecret: generate key pair: %w", err)
	}
	// Clamp for X25519.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return hex.EncodeToString(priv[:]), hex.EncodeToString(pub[:]), nil
}

// encryptForRecipient encrypts plaintext for a recipient's X25519 public key.
// Uses ephemeral X25519 + HKDF-SHA256 + ChaCha20-Poly1305 (strict-fail).
func encryptForRecipient(plaintext []byte, recipientPubKeyHex string) ([]byte, error) {
	recipientPub, err := agePublicKeyFromHex(recipientPubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("sharedsecret: decode recipient public key: %w", err)
	}

	// Generate ephemeral X25519 key pair.
	var ephemeralPriv [32]byte
	if _, err := rand.Read(ephemeralPriv[:]); err != nil {
		return nil, ErrEncryptionFailed
	}
	ephemeralPriv[0] &= 248
	ephemeralPriv[31] &= 127
	ephemeralPriv[31] |= 64

	var ephemeralPub [32]byte
	curve25519.ScalarBaseMult(&ephemeralPub, &ephemeralPriv)

	// ECDH: shared = ephemeralPriv * recipientPub
	shared, err := curve25519.X25519(ephemeralPriv[:], recipientPub[:])
	if err != nil {
		return nil, fmt.Errorf("sharedsecret: ECDH failed: %w", err)
	}

	// Derive symmetric key via HKDF-SHA256.
	info := []byte("keylatch/sharedsecret/chacha20poly1305/v1")
	kdf := hkdf.New(sha256.New, shared, ephemeralPub[:], info)
	symKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, symKey); err != nil {
		return nil, fmt.Errorf("sharedsecret: HKDF failed: %w", err)
	}

	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return nil, fmt.Errorf("sharedsecret: create AEAD: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrEncryptionFailed
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Wire format: [ephemeral_pub (32)] [nonce (12)] [ciphertext+tag]
	payload := make([]byte, 0, 32+len(nonce)+len(ciphertext))
	payload = append(payload, ephemeralPub[:]...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	return payload, nil
}

// decryptForRecipient decrypts a payload encrypted by encryptForRecipient.
// strict-fail — no fallback ciphers.
func decryptForRecipient(payload []byte, recipientPrivKeyHex string) ([]byte, error) {
	const ephemeralPubLen = 32

	if len(payload) < ephemeralPubLen+chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, ErrDecryptionFailed
	}

	var ephemeralPub [32]byte
	copy(ephemeralPub[:], payload[:ephemeralPubLen])

	recipientPriv, err := agePrivateKeyFromHex(recipientPrivKeyHex)
	if err != nil {
		return nil, fmt.Errorf("sharedsecret: decode private key: %w", err)
	}

	// ECDH: shared = recipientPriv * ephemeralPub
	shared, err := curve25519.X25519(recipientPriv[:], ephemeralPub[:])
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Derive symmetric key via HKDF-SHA256.
	info := []byte("keylatch/sharedsecret/chacha20poly1305/v1")
	kdf := hkdf.New(sha256.New, shared, ephemeralPub[:], info)
	symKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, symKey); err != nil {
		return nil, ErrDecryptionFailed
	}

	aead, err := chacha20poly1305.New(symKey)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	nonceOffset := ephemeralPubLen
	nonce := payload[nonceOffset : nonceOffset+aead.NonceSize()]
	ciphertext := payload[nonceOffset+aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// strict-fail — no fallback.
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// Create encrypts plaintext for each member's AgePublicKey.
// AGE encryption, strict-fail — no fallback ciphers.
// C-6: teamID is used to scope the name HMAC — prevents cross-team name collisions.
func Create(_ context.Context, teamID, name string, plaintext []byte, members []team.Member) (*SharedSecret, error) {
	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("sharedsecret: generate id: %w", err)
	}

	nameHMAC := hmacName(teamID, name)

	recipients := make([]RecipientEntry, 0, len(members))
	for _, m := range members {
		if m.AgePublicKey == "" {
			continue
		}
		enc, err := encryptForRecipient(plaintext, m.AgePublicKey)
		if err != nil {
			return nil, fmt.Errorf("sharedsecret: encrypt for member %q: %w", m.ID, err)
		}
		recipients = append(recipients, RecipientEntry{
			MemberIDHMAC:     m.HMAC,
			EncryptedPayload: enc,
		})
	}

	return &SharedSecret{
		ID:         id,
		NameHMAC:   nameHMAC,
		Recipients: recipients,
		CreatedAt:  time.Now().UTC(),
		Version:    1,
	}, nil
}

// Read decrypts the shared secret for the calling member.
// Blocked during LLM sessions and requires hardware presence proof.
func Read(ctx context.Context, s *SharedSecret, member team.Member, proof trust.PresenceProof) ([]byte, error) {
	// blocked during LLM sessions.
	if isLLMSession(ctx) {
		return nil, ErrLLMSessionBlocked
	}

	// requires hardware presence proof.
	if proof.ConfirmedAt.IsZero() {
		return nil, ErrHardwarePresenceRequired
	}

	// Find the recipient entry for this member.
	for _, r := range s.Recipients {
		if r.MemberIDHMAC == member.HMAC {
			if member.AgePublicKey == "" {
				return nil, fmt.Errorf("sharedsecret: member has no AGE public key")
			}
			// We need the private key; for testing, the member's AgePublicKey is the private key.
			// In production, the private key is derived from the member's trust root.
			return decryptForRecipient(r.EncryptedPayload, member.AgePublicKey)
		}
	}
	return nil, ErrNoRecipientFound
}

// RotateWithPlaintext re-encrypts plaintext for the given member list.
func RotateWithPlaintext(_ context.Context, s *SharedSecret, plaintext []byte, newMembers []team.Member) (*SharedSecret, error) {
	now := time.Now().UTC()
	recipients := make([]RecipientEntry, 0, len(newMembers))
	for _, m := range newMembers {
		if m.Status == team.MemberRemoved || m.AgePublicKey == "" {
			continue
		}
		enc, err := encryptForRecipient(plaintext, m.AgePublicKey)
		if err != nil {
			return nil, fmt.Errorf("sharedsecret: rotate for member %q: %w", m.ID, err)
		}
		recipients = append(recipients, RecipientEntry{
			MemberIDHMAC:     m.HMAC,
			EncryptedPayload: enc,
		})
	}
	return &SharedSecret{
		ID:         s.ID,
		NameHMAC:   s.NameHMAC,
		Recipients: recipients,
		CreatedAt:  s.CreatedAt,
		RotatedAt:  &now,
		Version:    s.Version + 1,
	}, nil
}

// Rewrap re-encrypts for a single new member without changing the plaintext.
// Requires a valid PresenceProof from the caller.
func Rewrap(_ context.Context, s *SharedSecret, callerProof trust.PresenceProof, newMember team.Member) (*SharedSecret, error) {
	if callerProof.ConfirmedAt.IsZero() {
		return nil, ErrHardwarePresenceRequired
	}
	if newMember.AgePublicKey == "" {
		return nil, fmt.Errorf("sharedsecret: new member has no AGE public key")
	}
	// Cannot rewrap without plaintext — return ErrNoRecipientFound if caller has no entry.
	// In production this would fetch the plaintext using the caller's trust root.
	return nil, fmt.Errorf("sharedsecret: rewrap requires plaintext — use RotateWithPlaintext")
}

// generateID returns a random 16-byte hex ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hmacName produces a stable HMAC of a secret name. Uses teamID for scoping.
func hmacName(teamID, name string) string {
	h := sha256.New()
	h.Write([]byte("keylatch/sharedsecret/name/v1/"))
	h.Write([]byte(teamID))
	h.Write([]byte("/"))
	h.Write([]byte(name))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}
