package keyops

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"

	"github.com/keylatch/keylatch/internal/audit"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const sessionBindExtension = "session-bind@openssh.com"

var errReadOnlyAgent = errors.New("keylatch ssh-agent lists and signs only")

type sshKey struct {
	ref     KeyRef
	signer  ssh.Signer
	private crypto.Signer
}

// loadSSHKeys reads every configured ssh key. The signers hold the parsed keys
// and are dropped when the caller is done.
func (s *Service) loadSSHKeys(ctx context.Context) ([]sshKey, error) {
	refs, err := s.policy.SSHKeys()
	if err != nil {
		return nil, err
	}
	var out []sshKey
	for _, ref := range refs {
		raw, err := s.keys.Fetch(ctx, ref.Policy.Secret)
		if err != nil {
			continue
		}
		cs, err := parsePrivateKey(raw)
		clear(raw)
		if err != nil {
			continue
		}
		sg, err := ssh.NewSignerFromSigner(cs)
		if err != nil {
			zeroSigner(cs)
			continue
		}
		out = append(out, sshKey{ref: ref, signer: sg, private: cs})
	}
	return out, nil
}

// SSHAgent serves the ssh-agent protocol for one client connection. It lists
// public keys and signs; keys cannot be added, removed or exported. When a
// key is restricted to host keys, signing needs a session-bind from the
// client naming one of them.
type SSHAgent struct {
	svc       *Service
	caller    Caller
	bound     string
	sessionID []byte
	hostKey   []byte
}

// NewSSHAgent returns the agent for one accepted connection.
func (s *Service) NewSSHAgent(c Caller) *SSHAgent { return &SSHAgent{svc: s, caller: c} }

var _ agent.ExtendedAgent = (*SSHAgent)(nil)

// List implements agent.Agent.
func (a *SSHAgent) List() ([]*agent.Key, error) {
	keys, err := a.svc.loadSSHKeys(context.Background())
	if err != nil {
		return nil, err
	}
	defer clearSSHKeys(keys)
	out := make([]*agent.Key, 0, len(keys))
	for _, k := range keys {
		pub := k.signer.PublicKey()
		out = append(out, &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: k.ref.Connection + "/" + k.ref.Field})
	}
	return out, nil
}

// Sign implements agent.Agent.
func (a *SSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags implements agent.ExtendedAgent.
func (a *SSHAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if flags != 0 && flags != agent.SignatureFlagRsaSha256 && flags != agent.SignatureFlagRsaSha512 {
		return nil, errors.New("unsupported signature flags")
	}
	ctx := context.Background()
	keys, err := a.svc.loadSSHKeys(ctx)
	if err != nil {
		return nil, err
	}
	defer clearSSHKeys(keys)
	want := key.Marshal()
	for _, k := range keys {
		if !bytes.Equal(k.signer.PublicKey().Marshal(), want) {
			continue
		}
		return a.signWith(ctx, k, data, flags)
	}
	_ = a.svc.record(ctx, a.caller, OpSSHSign, KeyRef{}, key.Type(), data, audit.OutcomeDenied, "no matching key")
	return nil, errors.New("key not found")
}

func (a *SSHAgent) signWith(ctx context.Context, k sshKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	alg := k.signer.PublicKey().Type()
	if alg != ssh.KeyAlgoRSA && flags != 0 {
		return nil, errors.New("RSA signature flags require an RSA key")
	}
	switch {
	case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha512 != 0:
		alg = ssh.KeyAlgoRSASHA512
	case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha256 != 0:
		alg = ssh.KeyAlgoRSASHA256
	case alg == ssh.KeyAlgoRSA:
		_ = a.svc.record(ctx, a.caller, OpSSHSign, k.ref, alg, data, audit.OutcomeDenied, "SHA-1 RSA signatures are refused")
		return nil, errors.New("SHA-1 RSA signatures are refused")
	}
	if hk := k.ref.Policy.SSHAgent.HostKeys; len(hk) > 0 {
		if !slices.Contains(hk, a.bound) || !a.matchesUserAuth(k.signer.PublicKey(), alg, data) {
			_ = a.svc.record(ctx, a.caller, OpSSHSign, k.ref, alg, data, audit.OutcomeDenied, "authentication does not match the allowed host session")
			return nil, errors.New("this key may sign only authentication for its bound allowed host session")
		}
	}
	as, ok := k.signer.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("key cannot sign")
	}
	sig, err := as.SignWithAlgorithm(rand.Reader, data, alg)
	if err != nil {
		_ = a.svc.record(ctx, a.caller, OpSSHSign, k.ref, alg, data, audit.OutcomeError, "signing failed")
		return nil, errors.New("signing failed")
	}
	if err := a.svc.record(ctx, a.caller, OpSSHSign, k.ref, alg, data, audit.OutcomeOK, ""); err != nil {
		return nil, errors.New("audit log is not writable")
	}
	return sig, nil
}

type sessionBind struct {
	HostKey      []byte
	SessionID    []byte
	Signature    []byte
	IsForwarding bool
}

func clearSSHKeys(keys []sshKey) {
	for _, key := range keys {
		zeroSigner(key.private)
	}
}

type sshUserAuth struct {
	SessionID    []byte
	Message      byte
	Username     string
	Service      string
	Method       string
	HasSignature bool
	Algorithm    string
	PublicKey    []byte
	Rest         []byte `ssh:"rest"`
}

func (a *SSHAgent) matchesUserAuth(key ssh.PublicKey, algorithm string, data []byte) bool {
	var request sshUserAuth
	if ssh.Unmarshal(data, &request) != nil || len(a.sessionID) == 0 || !bytes.Equal(request.SessionID, a.sessionID) ||
		request.Message != 50 || request.Service != "ssh-connection" || !request.HasSignature ||
		request.Algorithm != algorithm || !bytes.Equal(request.PublicKey, key.Marshal()) {
		return false
	}
	switch request.Method {
	case "publickey":
		return len(request.Rest) == 0
	case "publickey-hostbound-v00@openssh.com":
		var host struct{ Key []byte }
		return ssh.Unmarshal(request.Rest, &host) == nil && bytes.Equal(host.Key, a.hostKey)
	default:
		return false
	}
}

// Extension implements agent.ExtendedAgent. It accepts session-bind, which
// tells the agent which server host key the client's session is with.
func (a *SSHAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != sessionBindExtension {
		return nil, agent.ErrExtensionUnsupported
	}
	var b sessionBind
	if err := ssh.Unmarshal(contents, &b); err != nil {
		return nil, fmt.Errorf("session-bind: %w", err)
	}
	if a.bound != "" || b.IsForwarding || len(b.SessionID) == 0 || len(b.SessionID) > 64 {
		return nil, errors.New("session-bind: forwarding, rebinding, or invalid session identifier")
	}
	hostKey, err := ssh.ParsePublicKey(b.HostKey)
	if err != nil {
		return nil, fmt.Errorf("session-bind: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(b.Signature, &sig); err != nil {
		return nil, fmt.Errorf("session-bind: %w", err)
	}
	if err := hostKey.Verify(b.SessionID, &sig); err != nil {
		return nil, errors.New("session-bind: host key signature is invalid")
	}
	a.bound = ssh.FingerprintSHA256(hostKey)
	a.sessionID = slices.Clone(b.SessionID)
	a.hostKey = slices.Clone(b.HostKey)
	return nil, nil
}

// Add implements agent.Agent.
func (a *SSHAgent) Add(agent.AddedKey) error { return errReadOnlyAgent }

// Remove implements agent.Agent.
func (a *SSHAgent) Remove(ssh.PublicKey) error { return errReadOnlyAgent }

// RemoveAll implements agent.Agent.
func (a *SSHAgent) RemoveAll() error { return errReadOnlyAgent }

// Lock implements agent.Agent.
func (a *SSHAgent) Lock([]byte) error { return errReadOnlyAgent }

// Unlock implements agent.Agent.
func (a *SSHAgent) Unlock([]byte) error { return errReadOnlyAgent }

// Signers implements agent.Agent. Key material is never handed out.
func (a *SSHAgent) Signers() ([]ssh.Signer, error) { return nil, errReadOnlyAgent }
