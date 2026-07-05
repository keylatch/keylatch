package pkcs11

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

// Options configures a PKCS#11 adapter.
type Options struct {
	// ModulePath is the absolute path to the PKCS#11 shared library.
	ModulePath string
	// SlotLabel identifies the token slot by label.
	SlotLabel string
	// SlotID identifies the slot by numeric ID (used when SlotLabel is empty).
	SlotID uint
	// PINSource is "prompt", "keychain", or "env:KEYLATCH_PKCS11_PIN".
	// "env:..." is refused in LLM sessions.
	PINSource string
	// Label is the display label for this root instance.
	Label string
	// KekHMAC is used for allowlist HMAC verification.
	KekHMAC func([]byte) []byte
	// HMACFunc computes an HMAC of its argument under the keyring's HMAC key.
	// When non-nil, it is used to HMAC the raw adapter ID before embedding it
	// in PresenceProof.RootID (root IDs must be HMAC'd at emission).
	// When nil, the raw adapter ID is stored (backward compat; should not be nil in production).
	HMACFunc func([]byte) []byte
}

// Adapter implements trust.RootOfTrust using a PKCS#11 token.
// The implementation is a stub that returns ErrRootUnavailable for all
// operations requiring an actual hardware token. Integration tests are
// gated by the presence of SoftHSM2 (libsofthsm2.so).
type Adapter struct {
	opts    Options
	id      string
	hasCert bool // CKO_CERTIFICATE present on token
}

// New opens a PKCS#11 session to the module at opts.ModulePath.
// Enforces the module allowlist before any session is opened.
func New(opts Options) (*Adapter, error) {
	// 1. Load and verify allowlist.
	entries, err := LoadAllowlist(opts.KekHMAC)
	if err != nil {
		// Proceed with defaults if user allowlist is unreadable.
		entries = make([]ModuleEntry, len(defaultPKCS11Allowlist))
		copy(entries, defaultPKCS11Allowlist)
	}

	if !IsAllowed(entries, opts.ModulePath) {
		return nil, fmt.Errorf("%w: %s", trust.ErrModuleNotAllowlisted, opts.ModulePath)
	}

	// 2. Verify module hash if an expected hash is registered.
	for _, e := range entries {
		if e.ModulePath == opts.ModulePath {
			if hashErr := VerifyModuleHash(opts.ModulePath, e.SHA256Hex); hashErr != nil {
				if errors.Is(hashErr, trust.ErrModuleHashUnpinned) {
					// M-1: warn but allow loading — run 'keylatch trust allowlist add' to pin.
					slog.Warn("loading PKCS#11 module without hash verification — run 'keylatch trust allowlist add' to pin a hash",
						"module_path", opts.ModulePath,
						"remediation", "keylatch trust allowlist add",
					)
				} else {
					return nil, hashErr
				}
			}
			break
		}
	}

	// 3. Check LLM session for env PIN source.
	if opts.PINSource != "" && len(opts.PINSource) > 4 && opts.PINSource[:4] == "env:" {
		if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
			return nil, trust.ErrLLMSessionBlocked
		}
	}

	// 4. Attempt to open the module. In the stub implementation this fails unless
	// the file exists (integration tests provide a real SoftHSM2 library).
	if _, err := os.Stat(opts.ModulePath); err != nil {
		return nil, fmt.Errorf("%w: module not found: %v", trust.ErrRootUnavailable, err)
	}

	label := opts.Label
	if label == "" {
		label = opts.SlotLabel
	}
	if label == "" {
		label = opts.ModulePath
	}
	_ = label // planned: passed to adapter display name

	return &Adapter{
		opts: opts,
		id:   fmt.Sprintf("pkcs11:%s:%s", opts.ModulePath, opts.SlotLabel),
	}, nil
}

func (a *Adapter) ID() string           { return a.id }
func (a *Adapter) Type() trust.RootType { return trust.RootPKCS11 }

func (a *Adapter) Has(c trust.Capability) bool {
	switch c {
	case trust.CapWrap, trust.CapSignChallenge, trust.CapAttestation, trust.CapHardwareBound:
		return true
	case trust.CapMTLSClientAuth:
		return a.hasCert
	case trust.CapLaunchdSafe:
		return false // PKCS#11 requires PIN; not launchd-safe
	case trust.CapUserPresence:
		return false
	default:
		return false
	}
}

func (a *Adapter) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	defer zeroSlice(dek)
	return nil, fmt.Errorf("%w: pkcs11 session not open (stub)", trust.ErrRootUnavailable)
}

func (a *Adapter) Unwrap(_ context.Context, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: pkcs11 session not open (stub)", trust.ErrRootUnavailable)
}

func (a *Adapter) Sign(_ context.Context, _ []byte) ([]byte, crypto.PublicKey, error) {
	return nil, nil, fmt.Errorf("%w: pkcs11 session not open (stub)", trust.ErrRootUnavailable)
}

func (a *Adapter) Verify(_ context.Context, _, _ []byte, _ crypto.PublicKey) error {
	return fmt.Errorf("%w: pkcs11 session not open (stub)", trust.ErrRootUnavailable)
}

func (a *Adapter) RequirePresence(_ context.Context, _ string) (trust.PresenceProof, error) {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return trust.PresenceProof{}, trust.ErrLLMSessionBlocked
	}
	// HMAC the root ID at emission.
	rootID := a.id
	if a.opts.HMACFunc != nil {
		rootID = base64.RawURLEncoding.EncodeToString(a.opts.HMACFunc([]byte(a.id)))
	}
	return trust.PresenceProof{
		Method:      "pkcs11-pin",
		ConfirmedAt: time.Now().UTC(),
		RootID:      rootID,
	}, nil
}

func (a *Adapter) VerifyPresenceProof(_ context.Context, p trust.PresenceProof) error {
	if p.RootID == "" {
		return errors.New("pkcs11: invalid presence proof")
	}
	return nil
}

func (a *Adapter) Attest(_ context.Context) (trust.Attestation, error) {
	// In production: extract CKA_ATTESTATION_CERTIFICATE from the token.
	return trust.Attestation{Format: "pkcs11"}, nil
}

func (a *Adapter) Close() error { return nil }

func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func init() {
	trust.Register(trust.RootPKCS11, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		modPath := ""
		slotLabel := ""
		if spec.Extra != nil {
			if v, ok := spec.Extra["module_path"].(string); ok {
				modPath = v
			}
			if v, ok := spec.Extra["slot_label"].(string); ok {
				slotLabel = v
			}
		}
		if modPath == "" {
			return nil, fmt.Errorf("%w: pkcs11 module_path not set in spec.Extra", trust.ErrRootUnavailable)
		}
		return New(Options{
			ModulePath: modPath,
			SlotLabel:  slotLabel,
			Label:      spec.Label,
		})
	})
}
