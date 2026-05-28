//go:build darwin

// Package secureenclave implements a trust.RootOfTrust adapter backed by Apple Secure Enclave.
package secureenclave

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

// Options configures the Secure Enclave adapter.
type Options struct {
	// Label is the Access Control identifier for the SE key (used in persistence).
	Label string
	// PresenceMode is "any" (default) or "biometric".
	PresenceMode string
	// Namespace is an optional namespace for audit events.
	Namespace string
}

// Adapter implements trust.RootOfTrust using the macOS Secure Enclave.
//
// In the stub implementation (no CGo bridge compiled), all operations that
// require the SE return ErrRootUnavailable. A real integration test gated by
// KEYLATCH_E2E_SE=1 exercises the full bridge path.
type Adapter struct {
	opts Options
	id   string
}

// New returns a new Secure Enclave Adapter.
// Returns ErrRootUnavailable when the Secure Enclave is not accessible.
func New(opts Options) (*Adapter, error) {
	if !secureEnclaveAvailable() {
		return nil, fmt.Errorf("%w: Secure Enclave not available on this device", trust.ErrRootUnavailable)
	}
	label := opts.Label
	if label == "" {
		label = "keylatch-se"
	}
	return &Adapter{opts: opts, id: label}, nil
}

func (a *Adapter) ID() string           { return a.id }
func (a *Adapter) Type() trust.RootType { return trust.RootSecureEnclave }

func (a *Adapter) Has(c trust.Capability) bool {
	switch c {
	case trust.CapWrap, trust.CapSignChallenge, trust.CapUserPresence, trust.CapHardwareBound:
		return true
	case trust.CapLaunchdSafe:
		// SE requires user presence; not safe for launchd daemons.
		return false
	default:
		return false
	}
}

func (a *Adapter) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	defer zeroBytes(dek)
	if err := checkLLMSession(); err != nil {
		return nil, err
	}
	return seWrap(ctx, a.id, dek)
}

func (a *Adapter) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	return seUnwrap(ctx, a.id, wrapped)
}

func (a *Adapter) Sign(ctx context.Context, challenge []byte) ([]byte, crypto.PublicKey, error) {
	if err := checkLLMSession(); err != nil {
		return nil, nil, err
	}
	return seSign(ctx, a.id, challenge)
}

func (a *Adapter) Verify(_ context.Context, challenge, sig []byte, pub crypto.PublicKey) error {
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return trust.ErrCapabilityUnsupported
	}
	h := sha256.Sum256(challenge)
	r, s := new(big.Int), new(big.Int)
	// Parse DER-encoded ECDSA signature.
	if len(sig) < 2 || sig[0] != 0x30 {
		return errors.New("secureenclave: invalid signature format")
	}
	seqLen := int(sig[1])
	body := sig[2 : 2+seqLen]
	if len(body) < 2 || body[0] != 0x02 {
		return errors.New("secureenclave: invalid r integer")
	}
	rLen := int(body[1])
	r.SetBytes(body[2 : 2+rLen])
	body = body[2+rLen:]
	if len(body) < 2 || body[0] != 0x02 {
		return errors.New("secureenclave: invalid s integer")
	}
	sLen := int(body[1])
	s.SetBytes(body[2 : 2+sLen])

	if !ecdsa.Verify(key, h[:], r, s) {
		return trust.ErrAttestationInvalid
	}
	return nil
}

func (a *Adapter) RequirePresence(ctx context.Context, reason string) (trust.PresenceProof, error) {
	if err := checkLLMSession(); err != nil {
		return trust.PresenceProof{}, err
	}
	return seRequirePresence(ctx, a.id, reason)
}

func (a *Adapter) VerifyPresenceProof(_ context.Context, p trust.PresenceProof) error {
	// Structural check: confirm RootID matches and ConfirmedAt is non-zero.
	if p.RootID == "" {
		return errors.New("secureenclave: presence proof missing RootID")
	}
	if p.ConfirmedAt.IsZero() {
		return errors.New("secureenclave: presence proof ConfirmedAt is zero")
	}
	return nil
}

func (a *Adapter) Attest(_ context.Context) (trust.Attestation, error) {
	return trust.Attestation{Format: "apple"}, nil
}

func (a *Adapter) Close() error { return nil }

// zeroBytes zeroes a byte slice in place.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// checkLLMSession returns ErrLLMSessionBlocked if running inside an LLM session.
func checkLLMSession() error {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return trust.ErrLLMSessionBlocked
	}
	return nil
}

// --- stub bridge implementations (replaced by CGo on real builds) ---

// secureEnclaveAvailable returns true when the SE hardware is present.
// On real hardware this uses SecItemCopyMatching; here we return false as a stub.
func secureEnclaveAvailable() bool {
	// Real implementation probes SecItemCopyMatching with kSecAttrTokenIDSecureEnclave.
	// Stub: return false so that tests do not require hardware.
	return false
}

// seWrap encrypts dek using the SE key identified by label.
// Stub implementation: uses a software ECDH+AES-GCM simulation for compilation.
func seWrap(_ context.Context, _ string, dek []byte) ([]byte, error) {
	// Stub: in production this calls SEWrap from the ObjC bridge.
	// For testing without hardware, return ErrRootUnavailable.
	_ = dek
	return nil, trust.ErrRootUnavailable
}

// seUnwrap decrypts a blob produced by seWrap.
func seUnwrap(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, trust.ErrRootUnavailable
}

// seSign signs challenge using the SE private key.
// In production this uses SecKeyCreateSignature via the ObjC bridge.
// Stub: always returns ErrRootUnavailable.
func seSign(_ context.Context, _ string, _ []byte) ([]byte, crypto.PublicKey, error) {
	return nil, nil, trust.ErrRootUnavailable
}

// seRequirePresence triggers a LAContext.evaluatePolicy call.
func seRequirePresence(_ context.Context, rootID string, _ string) (trust.PresenceProof, error) {
	return trust.PresenceProof{}, trust.ErrRootUnavailable
}

func init() {
	trust.Register(trust.RootSecureEnclave, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		label := ""
		if spec.Extra != nil {
			if l, ok := spec.Extra["label"].(string); ok {
				label = l
			}
		}
		if label == "" {
			label = spec.ID
		}
		return New(Options{Label: label})
	})
}
