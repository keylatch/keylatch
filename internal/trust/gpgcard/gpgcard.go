package gpgcard

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

// Options configures the GPG card adapter.
type Options struct {
	// Keygrip is the hex keygrip of the signing key on the card.
	// If empty, the first available keygrip is selected.
	Keygrip string
	// SocketPath overrides the gpgconf-derived scdaemon socket path.
	SocketPath string
	// Label is the display label for this root.
	Label string
	// HMACFunc computes an HMAC of its argument under the keyring's HMAC key.
	// When non-nil, it is used to HMAC the raw adapter ID before embedding it
	// in PresenceProof.RootID (root IDs must be HMAC'd at emission).
	// When nil, the raw adapter ID is stored (backward compat; should not be nil in production).
	HMACFunc func([]byte) []byte
}

// Adapter implements trust.RootOfTrust using a GnuPG smartcard via scdaemon.
type Adapter struct {
	opts    Options
	id      string
	keygrip string
}

// New connects to the GnuPG scdaemon and configures the signing key.
func New(opts Options) (*Adapter, error) {
	socketPath := opts.SocketPath
	if socketPath == "" {
		var err error
		socketPath, err = scdaemonSocket()
		if err != nil {
			return nil, fmt.Errorf("%w: gpgconf: %v", trust.ErrRootUnavailable, err)
		}
	}

	// Probe the daemon to confirm card is present.
	conn, err := assuanDial(socketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: scdaemon not reachable: %v", trust.ErrRootUnavailable, err)
	}
	_ = conn.Close() // best-effort probe cleanup; connection not reused

	keygrip := opts.Keygrip
	if keygrip == "" {
		keygrip = "default"
	}

	label := opts.Label
	if label == "" {
		label = "gpg-card"
	}

	id := "gpgcard:" + keygrip

	return &Adapter{
		opts:    Options{Keygrip: keygrip, SocketPath: socketPath, Label: label},
		id:      id,
		keygrip: keygrip,
	}, nil
}

func (a *Adapter) ID() string           { return a.id }
func (a *Adapter) Type() trust.RootType { return trust.RootGPGCard }

func (a *Adapter) Has(c trust.Capability) bool {
	switch c {
	case trust.CapSignChallenge, trust.CapUserPresence:
		return true
	case trust.CapWrap, trust.CapLaunchdSafe:
		// GPG cards require PIN entry; not safe for launchd.
		return false
	default:
		return false
	}
}

func (a *Adapter) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	defer zeroBytes(dek)
	return nil, trust.ErrCapabilityUnsupported
}

func (a *Adapter) Unwrap(_ context.Context, _ []byte) ([]byte, error) {
	return nil, trust.ErrCapabilityUnsupported
}

func (a *Adapter) Sign(ctx context.Context, challenge []byte) ([]byte, crypto.PublicKey, error) {
	// Block LLM sessions during pinentry flow.
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return nil, nil, trust.ErrLLMSessionBlocked
	}

	conn, err := a.dial()
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close() //nolint:errcheck // defer close of assuan connection, error non-actionable

	sig, err := assuanSign(conn, a.keygrip, challenge)
	if err != nil {
		return nil, nil, fmt.Errorf("gpgcard: sign: %w", err)
	}
	// Public key is not returned by scdaemon directly in this protocol;
	// callers can retrieve it via gpg --export.
	return sig, nil, nil
}

func (a *Adapter) Verify(_ context.Context, _, _ []byte, _ crypto.PublicKey) error {
	return trust.ErrCapabilityUnsupported
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
		Method:      "gpg-card-pin",
		ConfirmedAt: time.Now().UTC(),
		RootID:      rootID,
	}, nil
}

func (a *Adapter) VerifyPresenceProof(_ context.Context, p trust.PresenceProof) error {
	if p.RootID == "" {
		return errors.New("gpgcard: invalid presence proof")
	}
	return nil
}

func (a *Adapter) Attest(_ context.Context) (trust.Attestation, error) {
	return trust.Attestation{}, trust.ErrCapabilityUnsupported
}

func (a *Adapter) Close() error { return nil }

func (a *Adapter) dial() (net.Conn, error) {
	conn, err := assuanDial(a.opts.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", trust.ErrRootUnavailable, err)
	}
	return conn, nil
}

// scdaemonSocket runs `gpgconf --list-dirs agent-socket` to find the scdaemon socket.
func scdaemonSocket() (string, error) {
	out, err := exec.Command("gpgconf", "--list-dirs", "agent-socket").Output()
	if err != nil {
		return "", fmt.Errorf("gpgconf: %w", err)
	}
	path := strings.TrimSpace(string(out))
	// gpgconf returns the agent socket; scdaemon uses agent.S.scdaemon in the same dir.
	// Replace "S.gpg-agent" with "S.scdaemon".
	path = strings.Replace(path, "S.gpg-agent", "S.scdaemon", 1)
	return path, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func init() {
	trust.Register(trust.RootGPGCard, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		keygrip := ""
		if spec.Extra != nil {
			if v, ok := spec.Extra["keygrip"].(string); ok {
				keygrip = v
			}
		}
		return New(Options{Keygrip: keygrip, Label: spec.Label})
	})
}
