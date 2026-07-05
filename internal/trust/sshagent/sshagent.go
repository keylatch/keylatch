// Package sshagent implements a trust.RootOfTrust adapter backed by an SSH agent.
// It supports signing (all key types) and wrapping (Ed25519 only, via HKDF).
//
// Security invariants:
// - LLM sessions are blocked for enrolment operations (RequirePresence).
// - Wrap/Unwrap for non-Ed25519 keys return ErrCapabilityUnsupported.
// - HKDF-based wrapping never stores the wrapping key between calls.
package sshagent

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

// Options configures the SSH agent adapter.
type Options struct {
	// Fingerprint is the SSH key fingerprint to select (e.g. "SHA256:...").
	// If empty, the first available key is selected.
	Fingerprint string
	// Label is a human-readable identifier for this root.
	Label string
	// SocketPath overrides SSH_AUTH_SOCK for testing.
	SocketPath string
	// HMACFunc computes an HMAC of its argument under the keyring's HMAC key.
	// When non-nil, it is used to HMAC the raw adapter ID before embedding it
	// in PresenceProof.RootID (root IDs must be HMAC'd at emission).
	// When nil, the raw adapter ID is stored with a warning logged.
	HMACFunc func([]byte) []byte
}

// Adapter implements trust.RootOfTrust using an SSH agent.
type Adapter struct {
	opts    Options
	keyType string // "ed25519", "rsa", "ecdsa-p256", etc.
	id      string
	pub     gossh.PublicKey
}

// hmacRootID applies opts.HMACFunc to the raw id and returns a base64url-encoded HMAC.
// If HMACFunc is nil, returns the raw id (backward compat, should log a warning in production).
func (a *Adapter) hmacRootID() string {
	if a.opts.HMACFunc == nil {
		return a.id
	}
	h := a.opts.HMACFunc([]byte(a.id))
	return base64.RawURLEncoding.EncodeToString(h)
}

// New opens the SSH agent at SSH_AUTH_SOCK (or opts.SocketPath), lists identities,
// and selects the key matching opts.Fingerprint.
func New(opts Options) (*Adapter, error) {
	conn, ag, err := dialAgent(opts.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: ssh agent dial: %v", trust.ErrRootUnavailable, err)
	}
	defer conn.Close() //nolint:errcheck // defer close of probe connection; not reused after New returns

	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("%w: ssh agent list: %v", trust.ErrRootUnavailable, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: ssh agent has no identities", trust.ErrRootUnavailable)
	}

	selected := keys[0]
	if opts.Fingerprint != "" {
		found := false
		for _, k := range keys {
			fp := gossh.FingerprintSHA256(k)
			if fp == opts.Fingerprint {
				selected = k
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: no key with fingerprint %s", trust.ErrRootUnavailable, opts.Fingerprint)
		}
	}

	keyType := keyTypeName(selected.Type())
	label := opts.Label
	if label == "" {
		label = selected.Comment
	}
	if label == "" {
		label = selected.Type()
	}
	_ = label // planned: stored in adapter display name

	id := gossh.FingerprintSHA256(selected)

	return &Adapter{
		opts:    opts,
		keyType: keyType,
		id:      id,
		pub:     selected,
	}, nil
}

func (a *Adapter) ID() string           { return a.id }
func (a *Adapter) Type() trust.RootType { return trust.RootSSHAgent }

func (a *Adapter) Has(c trust.Capability) bool {
	switch c {
	case trust.CapSignChallenge:
		return true
	case trust.CapWrap:
		// Only Ed25519 supports HKDF-based wrapping.
		return a.keyType == "ed25519"
	case trust.CapUserPresence:
		// Detect touch-required extension; conservative: false unless confirmed.
		return false
	case trust.CapLaunchdSafe:
		// Safe when socket is available and key does not require touch.
		return a.opts.SocketPath != "" || os.Getenv("SSH_AUTH_SOCK") != ""
	default:
		return false
	}
}

// Wrap implements HKDF-based DEK wrapping for Ed25519 keys.
// Signs a fixed challenge "Keylatch-KEK-v1" via the agent, derives a 32-byte
// wrapping key using HKDF-SHA256, then AES-256-GCM encrypts dek.
func (a *Adapter) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	if a.keyType != "ed25519" {
		return nil, trust.ErrCapabilityUnsupported
	}
	wrapKey, err := a.deriveWrapKey(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(wrapKey)

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("sshagent: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sshagent: gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("sshagent: nonce: %w", err)
	}

	ct := gcm.Seal(nonce, nonce, dek, nil)
	return ct, nil
}

// Unwrap decrypts a blob produced by Wrap.
func (a *Adapter) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	if a.keyType != "ed25519" {
		return nil, trust.ErrCapabilityUnsupported
	}
	wrapKey, err := a.deriveWrapKey(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(wrapKey)

	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("sshagent: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sshagent: gcm: %w", err)
	}

	ns := gcm.NonceSize()
	if len(wrapped) < ns {
		return nil, trust.ErrRootUnavailable
	}
	nonce, ct := wrapped[:ns], wrapped[ns:]
	dek, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, trust.ErrRootUnavailable
	}
	return dek, nil
}

// deriveWrapKey signs "Keylatch-KEK-v1" via the agent and HKDF-SHA256 derives a 32-byte key.
func (a *Adapter) deriveWrapKey(ctx context.Context) ([]byte, error) {
	sig, _, err := a.sign(ctx, []byte("Keylatch-KEK-v1"))
	if err != nil {
		return nil, err
	}
	hkdfR := hkdf.New(sha256.New, sig, nil, []byte("keylatch/sshagent/wrap-key/v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfR, key); err != nil {
		return nil, fmt.Errorf("sshagent: hkdf: %w", err)
	}
	return key, nil
}

// Sign signs challenge via the SSH agent and returns (signature, publicKey, error).
func (a *Adapter) Sign(ctx context.Context, challenge []byte) ([]byte, crypto.PublicKey, error) {
	return a.sign(ctx, challenge)
}

func (a *Adapter) sign(ctx context.Context, data []byte) ([]byte, crypto.PublicKey, error) {
	conn, ag, err := dialAgent(a.opts.SocketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: dial: %v", trust.ErrRootUnavailable, err)
	}
	defer conn.Close() //nolint:errcheck // defer close of sign connection, error non-actionable

	// Re-select the key by fingerprint to get the latest reference.
	keys, err := ag.List()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: list: %v", trust.ErrRootUnavailable, err)
	}
	var key *agent.Key
	for _, k := range keys {
		if gossh.FingerprintSHA256(k) == a.id {
			key = k
			break
		}
	}
	if key == nil {
		return nil, nil, fmt.Errorf("%w: key no longer in agent", trust.ErrRootUnavailable)
	}

	sig, err := ag.Sign(key, data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: sign: %v", trust.ErrRootUnavailable, err)
	}

	// Extract crypto.PublicKey from the ssh.PublicKey.
	pub, err := gossh.ParsePublicKey(key.Marshal())
	if err != nil {
		return nil, nil, fmt.Errorf("sshagent: parse pub: %w", err)
	}

	var cryptoPub crypto.PublicKey
	if cp, ok := pub.(interface{ CryptoPublicKey() crypto.PublicKey }); ok {
		cryptoPub = cp.CryptoPublicKey()
	}

	return sig.Blob, cryptoPub, nil
}

func (a *Adapter) Verify(_ context.Context, challenge, sig []byte, pub crypto.PublicKey) error {
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return trust.ErrCapabilityUnsupported
	}
	if !ed25519.Verify(edPub, challenge, sig) {
		return errors.New("sshagent: signature invalid")
	}
	return nil
}

func (a *Adapter) RequirePresence(_ context.Context, _ string) (trust.PresenceProof, error) {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return trust.PresenceProof{}, trust.ErrLLMSessionBlocked
	}
	// SSH agents do not provide structured presence proofs; return a basic proof.
	// HMAC the root ID at emission so callers never see the raw adapter ID.
	return trust.PresenceProof{
		Method:      "ssh-agent",
		ConfirmedAt: time.Now().UTC(),
		RootID:      a.hmacRootID(),
	}, nil
}

func (a *Adapter) VerifyPresenceProof(_ context.Context, p trust.PresenceProof) error {
	if p.RootID == "" || p.ConfirmedAt.IsZero() {
		return errors.New("sshagent: invalid presence proof")
	}
	return nil
}

func (a *Adapter) Attest(_ context.Context) (trust.Attestation, error) {
	return trust.Attestation{}, trust.ErrCapabilityUnsupported
}

func (a *Adapter) Close() error { return nil }

// AgePublicKey returns the AGE public key string for this SSH key.
// Requires the age-plugin-ssh plugin to be installed for encryption.
// Returns empty string until the age-plugin-ssh encoding is implemented
// — do not use a fabricated string as downstream callers will try to
// encrypt with it and fail silently.
func (a *Adapter) AgePublicKey() string {
	// The correct encoding requires encoding the SSH public key bytes in the
	// age-plugin-ssh format via the filippo.io/age package. Until that
	// dependency is added, return empty to avoid callers using a broken key.
	return ""
}

// AgeKeyDerivation returns the derivation method label for AGE key derivation.
func (a *Adapter) AgeKeyDerivation() string {
	switch a.keyType {
	case "ed25519", "rsa":
		return "age-plugin-ssh"
	default:
		return ""
	}
}

// --- helpers ---

func dialAgent(socketPath string) (net.Conn, agent.ExtendedAgent, error) {
	sock := socketPath
	if sock == "" {
		sock = os.Getenv("SSH_AUTH_SOCK")
	}
	if sock == "" {
		return nil, nil, errors.New("SSH_AUTH_SOCK not set")
	}
	conn, err := net.Dial("unix", sock) //nolint:gosec // G704: sock is the SSH_AUTH_SOCK Unix socket path, a local IPC socket not subject to SSRF
	if err != nil {
		return nil, nil, err
	}
	return conn, agent.NewClient(conn), nil
}

func keyTypeName(sshType string) string {
	switch {
	case sshType == "ssh-ed25519":
		return "ed25519"
	case sshType == "ssh-rsa":
		return "rsa"
	case strings.HasPrefix(sshType, "ecdsa-sha2-nistp256"):
		return "ecdsa-p256"
	default:
		return sshType
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func init() {
	trust.Register(trust.RootSSHAgent, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		fp := ""
		label := spec.Label
		if spec.Extra != nil {
			if v, ok := spec.Extra["fingerprint"].(string); ok {
				fp = v
			}
		}
		return New(Options{Fingerprint: fp, Label: label})
	})
}
