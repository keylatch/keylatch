//go:build !windows

package sshagent

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

func trsClearLLMEnv(t *testing.T) {
	t.Helper()
	for _, s := range llmcontext.Signals {
		t.Setenv(s.EnvKey, "")
	}
}

// trsAgent wraps a keyring so individual calls can be made to fail.
type trsAgent struct {
	agent.Agent
	listCalls atomic.Int32
	failListN atomic.Int32 // fail the Nth List call (1-based); 0 = never
	failSign  atomic.Bool
}

func (a *trsAgent) List() ([]*agent.Key, error) {
	n := a.listCalls.Add(1)
	if f := a.failListN.Load(); f != 0 && n == f {
		return nil, errors.New("list refused")
	}
	return a.Agent.List()
}

func (a *trsAgent) Sign(key gossh.PublicKey, data []byte) (*gossh.Signature, error) {
	if a.failSign.Load() {
		return nil, errors.New("sign refused")
	}
	return a.Agent.Sign(key, data)
}

func trsShortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "trs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func trsServe(t *testing.T, ag agent.Agent) string {
	t.Helper()
	sock := filepath.Join(trsShortDir(t), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = agent.ServeAgent(ag, c)
			}()
		}
	}()
	return sock
}

type trsKeys struct {
	ed, ec, rsa gossh.PublicKey
}

func trsKeyring(t *testing.T) (agent.Agent, trsKeys) {
	t.Helper()
	kr := agent.NewKeyring()
	var ks trsKeys

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []agent.AddedKey{
		{PrivateKey: edPriv, Comment: "ed-key"},
		{PrivateKey: ecPriv},
		{PrivateKey: rsaPriv, Comment: "rsa-key"},
	} {
		if err := kr.Add(k); err != nil {
			t.Fatal(err)
		}
	}
	if ks.ed, err = gossh.NewPublicKey(edPub); err != nil {
		t.Fatal(err)
	}
	if ks.ec, err = gossh.NewPublicKey(&ecPriv.PublicKey); err != nil {
		t.Fatal(err)
	}
	if ks.rsa, err = gossh.NewPublicKey(&rsaPriv.PublicKey); err != nil {
		t.Fatal(err)
	}
	return kr, ks
}

func TestNewSelectsKeyByFingerprint(t *testing.T) {
	trsClearLLMEnv(t)
	kr, ks := trsKeyring(t)
	sock := trsServe(t, kr)

	first, err := New(Options{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != gossh.FingerprintSHA256(ks.ed) || first.keyType != "ed25519" || first.Type() != trust.RootSSHAgent {
		t.Fatalf("default selection = %q (%s)", first.ID(), first.keyType)
	}

	cases := []struct {
		pub      gossh.PublicKey
		keyType  string
		canWrap  bool
		ageDeriv string
	}{
		{ks.ec, "ecdsa-p256", false, ""},
		{ks.rsa, "rsa", false, "age-plugin-ssh"},
		{ks.ed, "ed25519", true, "age-plugin-ssh"},
	}
	for _, tc := range cases {
		fp := gossh.FingerprintSHA256(tc.pub)
		a, err := New(Options{SocketPath: sock, Fingerprint: fp})
		if err != nil {
			t.Fatalf("%s: %v", tc.keyType, err)
		}
		if a.ID() != fp || a.keyType != tc.keyType {
			t.Errorf("%s: id=%q type=%q", tc.keyType, a.ID(), a.keyType)
		}
		if a.Has(trust.CapWrap) != tc.canWrap || !a.Has(trust.CapSignChallenge) {
			t.Errorf("%s: wrap=%v", tc.keyType, a.Has(trust.CapWrap))
		}
		if a.Has(trust.CapUserPresence) || a.Has(trust.CapAttestation) || a.Has(trust.CapHardwareBound) {
			t.Errorf("%s: unexpected capability", tc.keyType)
		}
		if a.AgeKeyDerivation() != tc.ageDeriv || a.AgePublicKey() != "" {
			t.Errorf("%s: age derivation = %q", tc.keyType, a.AgeKeyDerivation())
		}
	}

	_, err = New(Options{SocketPath: sock, Fingerprint: "SHA256:nope"})
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "no key with fingerprint SHA256:nope") {
		t.Fatalf("unknown fingerprint: err = %v", err)
	}
}

func TestNewAgentFailures(t *testing.T) {
	empty := trsServe(t, agent.NewKeyring())
	if _, err := New(Options{SocketPath: empty}); !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "no identities") {
		t.Fatalf("empty agent: err = %v", err)
	}

	kr, _ := trsKeyring(t)
	fa := &trsAgent{Agent: kr}
	fa.failListN.Store(1)
	failing := trsServe(t, fa)
	if _, err := New(Options{SocketPath: failing}); !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "ssh agent list") {
		t.Fatalf("list failure: err = %v", err)
	}

	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := New(Options{}); !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "SSH_AUTH_SOCK not set") {
		t.Fatalf("no socket: err = %v", err)
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	trsClearLLMEnv(t)
	kr, _ := trsKeyring(t)
	a, err := New(Options{SocketPath: trsServe(t, kr)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	msg := []byte("approve deploy")
	sig, pub, err := a.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Fatalf("pub type = %T", pub)
	}
	if err := a.Verify(ctx, msg, sig, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := a.Verify(ctx, []byte("other"), sig, pub); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("tampered message: err = %v", err)
	}
	if err := a.Verify(ctx, msg, sig, "not a key"); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Fatalf("non-ed25519 key: err = %v", err)
	}
}

func TestSignReturnsCryptoKeyForRSA(t *testing.T) {
	kr, ks := trsKeyring(t)
	a, err := New(Options{SocketPath: trsServe(t, kr), Fingerprint: gossh.FingerprintSHA256(ks.rsa)})
	if err != nil {
		t.Fatal(err)
	}
	sig, pub, err := a.Sign(context.Background(), []byte("m"))
	if err != nil || len(sig) == 0 {
		t.Fatalf("sig=%d err=%v", len(sig), err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("pub type = %T", pub)
	}
	if err := a.Verify(context.Background(), []byte("m"), sig, pub); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Fatalf("Verify rsa: %v", err)
	}
}

func TestWrapUnwrapRules(t *testing.T) {
	kr, ks := trsKeyring(t)
	sock := trsServe(t, kr)
	ctx := context.Background()

	rsaA, err := New(Options{SocketPath: sock, Fingerprint: gossh.FingerprintSHA256(ks.rsa)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rsaA.Wrap(ctx, []byte("dek")); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Fatalf("rsa Wrap: %v", err)
	}
	if _, err := rsaA.Unwrap(ctx, []byte("x")); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Fatalf("rsa Unwrap: %v", err)
	}

	ed, err := New(Options{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := ed.Wrap(ctx, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ed.Unwrap(ctx, ct[:5]); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("short blob: %v", err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := ed.Unwrap(ctx, ct); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("tampered blob: %v", err)
	}
}

func TestOperationsFailWhenAgentChanges(t *testing.T) {
	kr, ks := trsKeyring(t)
	wrapped := &trsAgent{Agent: kr}
	sock := trsServe(t, wrapped)
	ctx := context.Background()

	a, err := New(Options{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}

	wrapped.failSign.Store(true)
	if _, _, err := a.Sign(ctx, []byte("m")); !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "sign: agent: failed to sign") {
		t.Fatalf("sign refused: %v", err)
	}
	if _, err := a.Wrap(ctx, []byte("k")); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("Wrap with failing sign: %v", err)
	}
	if _, err := a.Unwrap(ctx, make([]byte, 40)); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("Unwrap with failing sign: %v", err)
	}
	wrapped.failSign.Store(false)

	wrapped.failListN.Store(wrapped.listCalls.Load() + 1)
	if _, _, err := a.Sign(ctx, []byte("m")); !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "list") {
		t.Fatalf("list refused: %v", err)
	}

	if err := kr.Remove(ks.ed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Sign(ctx, []byte("m")); !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "key no longer in agent") {
		t.Fatalf("removed key: %v", err)
	}

	a.opts.SocketPath = filepath.Join(trsShortDir(t), "gone.sock")
	if _, _, err := a.Sign(ctx, []byte("m")); !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "dial") {
		t.Fatalf("agent gone: %v", err)
	}
}

func TestLaunchdSafetyFollowsSocketAvailability(t *testing.T) {
	a := &Adapter{keyType: "ed25519"}
	t.Setenv("SSH_AUTH_SOCK", "")
	if a.Has(trust.CapLaunchdSafe) {
		t.Fatal("launchd-safe without any socket")
	}
	t.Setenv("SSH_AUTH_SOCK", "/run/agent.sock")
	if !a.Has(trust.CapLaunchdSafe) {
		t.Fatal("SSH_AUTH_SOCK set should be launchd-safe")
	}
	t.Setenv("SSH_AUTH_SOCK", "")
	a.opts.SocketPath = "/x.sock"
	if !a.Has(trust.CapLaunchdSafe) {
		t.Fatal("explicit socket should be launchd-safe")
	}
}

func TestPresenceProofChecks(t *testing.T) {
	trsClearLLMEnv(t)
	a := &Adapter{id: "SHA256:abc"}
	ctx := context.Background()
	p, err := a.RequirePresence(ctx, "why")
	if err != nil || p.Method != "ssh-agent" || p.RootID != "SHA256:abc" {
		t.Fatalf("proof = %+v, %v", p, err)
	}
	if err := a.VerifyPresenceProof(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyPresenceProof(ctx, trust.PresenceProof{RootID: "r"}); err == nil {
		t.Fatal("proof without timestamp accepted")
	}
	if _, err := a.Attest(ctx); !errors.Is(err, trust.ErrCapabilityUnsupported) {
		t.Fatalf("Attest: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CLAUDECODE", "1")
	if _, err := a.RequirePresence(ctx, "why"); !errors.Is(err, trust.ErrLLMSessionBlocked) {
		t.Fatalf("LLM session: %v", err)
	}
}

func TestKeyTypeName(t *testing.T) {
	for in, want := range map[string]string{
		"ssh-ed25519":                "ed25519",
		"ssh-rsa":                    "rsa",
		"ecdsa-sha2-nistp256":        "ecdsa-p256",
		"ecdsa-sha2-nistp384":        "ecdsa-sha2-nistp384",
		"sk-ssh-ed25519@openssh.com": "sk-ssh-ed25519@openssh.com",
	} {
		if got := keyTypeName(in); got != want {
			t.Errorf("keyTypeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegisteredFactoryUsesAuthSock(t *testing.T) {
	kr, ks := trsKeyring(t)
	sock := trsServe(t, kr)
	t.Setenv("SSH_AUTH_SOCK", sock)

	fp := gossh.FingerprintSHA256(ks.rsa)
	r, err := trust.New(trust.RootSpec{Type: trust.RootSSHAgent, Label: "work", Extra: map[string]any{"fingerprint": fp}})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID() != fp {
		t.Fatalf("ID = %q, want %q", r.ID(), fp)
	}
	r, err = trust.New(trust.RootSpec{Type: trust.RootSSHAgent})
	if err != nil || r.ID() != gossh.FingerprintSHA256(ks.ed) {
		t.Fatalf("default key: %v, %v", r, err)
	}
}
