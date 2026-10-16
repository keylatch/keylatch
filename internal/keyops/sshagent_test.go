package keyops

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func sshPolicy(hostKeys ...string) staticPolicy {
	return staticPolicy{conns: map[string]map[string]FieldPolicy{
		"deploy": {"KEY": {Secret: "k", SSHAgent: &SSHPolicy{HostKeys: hostKeys}}},
	}}
}

func agentClient(t *testing.T, s *Service) (agent.ExtendedAgent, *SSHAgent) {
	t.Helper()
	a := s.NewSSHAgent(Caller{Kind: "agent", Constrained: true})
	c1, c2 := net.Pipe()
	go func() { _ = agent.ServeAgent(a, c2) }()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	return agent.NewClient(c1), a
}

func TestSSHAgentListsAndSigns(t *testing.T) {
	k := newTestKeys(t)
	s, cap := service(t, sshPolicy(), mapKeys{"k": k.ed})
	client, _ := agentClient(t, s)

	keys, err := client.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "deploy/KEY" {
		t.Fatalf("list: %v %v", keys, err)
	}
	pub, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		t.Fatal(err)
	}
	if got := ssh.PublicKey(pub).Marshal(); string(got) != string(mustSSHPub(t, k.edPub).Marshal()) {
		t.Fatal("agent lists a different key")
	}

	data := []byte("data to sign")
	sig, err := client.Sign(pub, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if !strings.Contains(cap.dump(), `"operation":"ssh_sign"`) {
		t.Fatal("ssh signing is not audited")
	}
	assertAbsent(t, cap.dump(), k.ed)
}

func mustSSHPub(t *testing.T, k ed25519.PublicKey) ssh.PublicKey {
	t.Helper()
	p, err := ssh.NewPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSSHAgentIsReadOnly(t *testing.T) {
	k := newTestKeys(t)
	s, _ := service(t, sshPolicy(), mapKeys{"k": k.ed})
	client, _ := agentClient(t, s)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := client.Add(agent.AddedKey{PrivateKey: priv}); err == nil {
		t.Fatal("a key was added")
	}
	keys, _ := client.List()
	pub, _ := ssh.ParsePublicKey(keys[0].Blob)
	if err := client.Remove(pub); err == nil {
		t.Fatal("a key was removed")
	}
	if err := client.RemoveAll(); err == nil {
		t.Fatal("keys were removed")
	}
	if _, err := client.Sign(mustSSHPub(t, k.edPub), []byte("x")); err != nil {
		t.Fatalf("signing with the listed key: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := client.Sign(mustSSHPub(t, other), []byte("x")); err == nil {
		t.Fatal("signed with an unlisted key")
	}
}

func TestSSHAgentOnlyServesKeysWithSSHEnabled(t *testing.T) {
	k := newTestKeys(t)
	s, _ := service(t, fullPolicy("k", []string{"sign"}, EdDSA), mapKeys{"k": k.ed})
	client, _ := agentClient(t, s)
	if keys, err := client.List(); err != nil || len(keys) != 0 {
		t.Fatalf("a key without ssh_agent was listed: %v %v", keys, err)
	}
}

func TestSSHAgentRefusesSHA1RSA(t *testing.T) {
	k := newTestKeys(t)
	s, _ := service(t, sshPolicy(), mapKeys{"k": k.rsaKey})
	client, _ := agentClient(t, s)
	keys, _ := client.List()
	pub, _ := ssh.ParsePublicKey(keys[0].Blob)
	if _, err := client.Sign(pub, []byte("x")); err == nil {
		t.Fatal("an ssh-rsa (SHA-1) signature was produced")
	}
	sig, err := client.SignWithFlags(pub, []byte("x"), agent.SignatureFlagRsaSha256)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("format %s", sig.Format)
	}
}

func hostKeyBind(t *testing.T) (ssh.PublicKey, []byte) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := []byte("session identifier of 32 bytes!!")
	sig, err := hostSigner.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	payload := ssh.Marshal(sessionBind{
		HostKey:   hostSigner.PublicKey().Marshal(),
		SessionID: sessionID,
		Signature: ssh.Marshal(sig),
	})
	return hostSigner.PublicKey(), payload
}

func TestSSHAgentPerHostRestriction(t *testing.T) {
	k := newTestKeys(t)
	allowedHost, allowedBind := hostKeyBind(t)
	_, otherBind := hostKeyBind(t)
	s, cap := service(t, sshPolicy(ssh.FingerprintSHA256(allowedHost)), mapKeys{"k": k.ed})
	pub := mustSSHPub(t, k.edPub)

	client, _ := agentClient(t, s)
	if _, err := client.Sign(pub, []byte("x")); err == nil {
		t.Fatal("signed with no host binding")
	}

	if _, err := client.Extension(sessionBindExtension, otherBind); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(pub, []byte("x")); err == nil {
		t.Fatal("signed for a host that is not allowed")
	}

	if _, err := client.Extension(sessionBindExtension, allowedBind); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(pub, []byte("x")); err != nil {
		t.Fatalf("refused for an allowed host: %v", err)
	}
	if !strings.Contains(cap.dump(), `"outcome":"denied"`) {
		t.Fatal("host refusals are not audited")
	}
}

func TestSSHAgentRejectsForgedBind(t *testing.T) {
	k := newTestKeys(t)
	host, bind := hostKeyBind(t)
	s, _ := service(t, sshPolicy(ssh.FingerprintSHA256(host)), mapKeys{"k": k.ed})
	client, _ := agentClient(t, s)

	forged := append([]byte(nil), bind...)
	forged[len(forged)-6] ^= 0xff
	_, _ = client.Extension(sessionBindExtension, forged)
	if _, err := client.Sign(mustSSHPub(t, k.edPub), []byte("x")); err == nil {
		t.Fatal("a forged session-bind unlocked signing")
	}
}
