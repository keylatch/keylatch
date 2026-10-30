//go:build !windows

package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type memoryKeys map[string][]byte

func (m memoryKeys) Fetch(_ context.Context, secret string) ([]byte, error) {
	v, ok := m[secret]
	if !ok {
		return nil, fmt.Errorf("%w: missing", keyops.ErrNotFound)
	}
	return append([]byte(nil), v...), nil
}

type recordedAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordedAudit) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordedAudit) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

func (r *recordedAudit) dump() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, _ := json.Marshal(r.events)
	return string(b)
}

type keyDaemon struct {
	socket, agentSocket string
	env                 map[string]string
	audit               *recordedAudit
}

func pemOf(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func startKeyDaemon(t *testing.T, seed []keyops.Change, keys memoryKeys) *keyDaemon {
	t.Helper()
	return startKeyDaemonWith(t, seed, keys, nil)
}

func startKeyDaemonWith(t *testing.T, seed []keyops.Change, keys memoryKeys, tune func(*Config)) *keyDaemon {
	t.Helper()
	dir, err := os.MkdirTemp("", "klk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	store := keyops.NewStore(filepath.Join(dir, "key-operations.json"), keyops.MACKey(bytes.Repeat([]byte{3}, 32)))
	rec := &recordedAudit{}
	svc, err := keyops.New(store, keys, rec)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := keyops.NewAdmin(store, rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range seed {
		if err := admin.Allow(context.Background(), human, ch); err != nil {
			t.Fatal(err)
		}
	}
	rec.reset()

	d := &keyDaemon{
		socket:      filepath.Join(dir, "s", "k.sock"),
		agentSocket: filepath.Join(dir, "s", "agent.sock"),
		audit:       rec,
	}
	d.env = map[string]string{"KEYLATCH_CONFIG_DIR": filepath.Join(dir, "state"), "KEYLATCH_SOCKET": d.socket}

	ln, err := Listen(d.socket)
	if err != nil {
		t.Fatal(err)
	}
	aln, err := Listen(d.agentSocket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cfg := Config{Env: lookupOf(d.env), Binary: "/bin/false", Keys: svc, KeyAdmin: admin}
	cfg.KeyPresence = keyPresenceFunc(func(context.Context, presence.Action, string) error { return nil })
	if tune != nil {
		tune(&cfg)
	}
	srv := NewServer(cfg)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = srv.Serve(ctx, ln) }()
	go func() { defer wg.Done(); _ = srv.ServeSSHAgent(ctx, aln) }()
	t.Cleanup(func() { cancel(); wg.Wait() })
	return d
}

func runKeyCLI(t *testing.T, env map[string]string, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookupOf(env), args, IO{In: strings.NewReader(stdin), Out: &out, ErrOut: &errOut})
	if !handled {
		t.Fatalf("keylatch %v was not handled by the daemon", args)
	}
	return code, out.String(), errOut.String()
}

func keyBytesForms(b []byte) []string {
	out := []string{string(b), hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b)}
	if blk, _ := pem.Decode(b); blk != nil {
		out = append(out, base64.StdEncoding.EncodeToString(blk.Bytes), base64.RawURLEncoding.EncodeToString(blk.Bytes), hex.EncodeToString(blk.Bytes))
	}
	return out
}

func requireAbsent(t *testing.T, where, haystack string, keys ...[]byte) {
	t.Helper()
	for _, k := range keys {
		for _, f := range keyBytesForms(k) {
			if len(f) >= 16 && strings.Contains(haystack, f) {
				t.Fatalf("key material appears in %s", where)
			}
		}
	}
}

var human = keyops.Caller{Kind: "human"}

var keySeed = []keyops.Change{
	{Connection: "app-local", Field: "RELEASE_KEY", Secret: "ed", Operations: []string{"sign", "verify", "jwt_sign"}, Algorithms: []string{"EdDSA"}},
	{Connection: "app-local", Field: "HMAC_KEY", Secret: "hmac", Operations: []string{"sign", "jwt_sign"}, Algorithms: []string{"HS256"}},
	{Connection: "app-local", Field: "ES_KEY", Secret: "es", Operations: []string{"jwt_sign"}, Algorithms: []string{"ES256"}},
	{Connection: "app-local", Field: "DATA_KEY", Secret: "aes", Operations: []string{"encrypt", "decrypt"}, Algorithms: []string{"A256GCM"}},
	{Connection: "open-data", Field: "DATA_KEY", Secret: "aes", Operations: []string{"encrypt", "decrypt"}, Algorithms: []string{"A256GCM"}, AgentDecrypt: true},
	{Connection: "deploy", Field: "SSH_KEY", Secret: "ed", SSHAgent: true},
}

func TestKeyOperationsThroughDaemon(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	esPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hmacKey := bytes.Repeat([]byte{0x5a, 0xc3, 0x11, 0x9e}, 12)
	aesKey := bytes.Repeat([]byte{0xa7, 0x42}, 16)
	keys := memoryKeys{"ed": pemOf(t, edPriv), "es": pemOf(t, esPriv), "hmac": hmacKey, "aes": aesKey}
	d := startKeyDaemon(t, keySeed, keys)
	claims := `{"sub":"release","iss":"keylatch"}`

	var transcript strings.Builder
	record := func(code int, out, errOut string) { fmt.Fprintf(&transcript, "%d|%s|%s", code, out, errOut) }

	t.Run("jwt EdDSA verifies with the real key", func(t *testing.T) {
		code, out, errOut := runKeyCLI(t, d.env, claims, "key", "jwt-sign", "app-local", "--field", "RELEASE_KEY")
		record(code, out, errOut)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		tok, err := jwt.Parse(strings.TrimSpace(out), func(*jwt.Token) (any, error) { return edPub, nil }, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("keylatch"))
		if err != nil || !tok.Valid {
			t.Fatalf("token does not verify: %v", err)
		}
	})
	t.Run("jwt HS256 verifies with the real key", func(t *testing.T) {
		code, out, errOut := runKeyCLI(t, d.env, claims, "key", "jwt-sign", "app-local", "--field=HMAC_KEY", "--kid", "k1")
		record(code, out, errOut)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		tok, err := jwt.Parse(strings.TrimSpace(out), func(*jwt.Token) (any, error) { return hmacKey, nil }, jwt.WithValidMethods([]string{"HS256"}))
		if err != nil || !tok.Valid || tok.Header["kid"] != "k1" {
			t.Fatalf("token does not verify: %v", err)
		}
	})
	t.Run("jwt ES256 verifies with the real key", func(t *testing.T) {
		code, out, errOut := runKeyCLI(t, d.env, claims, "key", "jwt-sign", "app-local", "--field", "ES_KEY")
		record(code, out, errOut)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		if tok, err := jwt.Parse(strings.TrimSpace(out), func(*jwt.Token) (any, error) { return &esPriv.PublicKey, nil }, jwt.WithValidMethods([]string{"ES256"})); err != nil || !tok.Valid {
			t.Fatalf("token does not verify: %v", err)
		}
	})
	t.Run("sign and verify through files", func(t *testing.T) {
		dir := t.TempDir()
		msg, sig := filepath.Join(dir, "msg"), filepath.Join(dir, "sig")
		_ = os.WriteFile(msg, []byte("artifact bytes"), 0o600)
		code, out, errOut := runKeyCLI(t, d.env, "", "key", "sign", "app-local", "--field", "RELEASE_KEY", "--in", msg, "--out", sig, "--encoding", "hex")
		record(code, out, errOut)
		if code != 0 || out != "" {
			t.Fatalf("sign: exit %d stdout %q stderr %q", code, out, errOut)
		}
		raw, _ := os.ReadFile(sig)
		want, _ := hex.DecodeString(strings.TrimSpace(string(raw)))
		if !ed25519.Verify(edPub, []byte("artifact bytes"), want) {
			t.Fatal("signature does not verify with the real key")
		}
		if code, _, errOut = runKeyCLI(t, d.env, "", "key", "verify", "app-local", "--field", "RELEASE_KEY", "--in", msg, "--sig", sig, "--encoding", "hex"); code != 0 {
			t.Fatalf("verify: exit %d %s", code, errOut)
		}
		_ = os.WriteFile(msg, []byte("tampered"), 0o600)
		if code, _, _ = runKeyCLI(t, d.env, "", "key", "verify", "app-local", "--field", "RELEASE_KEY", "--in", msg, "--sig", sig, "--encoding", "hex"); code != 1 {
			t.Fatalf("a tampered input verified: exit %d", code)
		}
	})
	t.Run("encrypt then decrypt for a human", func(t *testing.T) {
		code, ct, errOut := runKeyCLI(t, d.env, "plaintext!", "key", "encrypt", "app-local", "--field", "DATA_KEY", "--encoding", "base64")
		record(code, ct, errOut)
		if code != 0 {
			t.Fatalf("encrypt: %d %s", code, errOut)
		}
		code, pt, errOut := runKeyCLI(t, d.env, ct, "key", "decrypt", "app-local", "--field", "DATA_KEY", "--encoding", "base64")
		if code != 0 || pt != "plaintext!" {
			t.Fatalf("decrypt: %d %q %s", code, pt, errOut)
		}
	})
	t.Run("not on the allowlist is refused", func(t *testing.T) {
		for name, args := range map[string][]string{
			"operation": {"key", "verify", "app-local", "--field", "HMAC_KEY", "--sig", "/dev/null"},
			"algorithm": {"key", "sign", "app-local", "--field", "HMAC_KEY", "--alg", "HS512"},
			"jwt alg":   {"key", "jwt-sign", "app-local", "--field", "HMAC_KEY", "--alg", "ES256"},
		} {
			code, out, errOut := runKeyCLI(t, d.env, claims, args...)
			record(code, out, errOut)
			if code != 2 || out != "" {
				t.Errorf("%s: exit %d stdout %q stderr %q", name, code, out, errOut)
			}
		}
		if code, _, _ := runKeyCLI(t, d.env, claims, "key", "sign", "nope"); code != 3 {
			t.Errorf("unknown connection: exit %d", code)
		}
	})
	t.Run("decrypt is refused for agent callers by default", func(t *testing.T) {
		env := map[string]string{"KEYLATCH_AGENT_SESSION": "1"}
		for k, v := range d.env {
			env[k] = v
		}
		code, ct, _ := runKeyCLI(t, env, "agent data", "key", "encrypt", "app-local", "--field", "DATA_KEY", "--encoding", "hex")
		if code != 0 {
			t.Fatalf("agent encrypt should be allowed: %d", code)
		}
		code, pt, errOut := runKeyCLI(t, env, ct, "key", "decrypt", "app-local", "--field", "DATA_KEY", "--encoding", "hex")
		if code != 2 || pt != "" || !strings.Contains(errOut, "plaintext") {
			t.Fatalf("agent decrypt: exit %d stdout %q stderr %q", code, pt, errOut)
		}
		code, ct, _ = runKeyCLI(t, env, "agent data", "key", "encrypt", "open-data")
		if code != 0 {
			t.Fatal("encrypt failed")
		}
		if code, pt, _ = runKeyCLI(t, env, ct, "key", "decrypt", "open-data"); code != 0 || pt != "agent data" {
			t.Fatalf("decrypt the connection allows for agents: %d %q", code, pt)
		}
	})
	t.Run("value verbs stay refused for agents", func(t *testing.T) {
		env := map[string]string{"KEYLATCH_AGENT_SESSION": "1"}
		for k, v := range d.env {
			env[k] = v
		}
		if code, _, _ := runKeyCLI(t, env, "", "get", "app-local", "RELEASE_KEY"); code != 2 {
			t.Fatalf("get: exit %d", code)
		}
	})

	for _, k := range [][]byte{keys["ed"], keys["es"], hmacKey, aesKey} {
		requireAbsent(t, "client output", transcript.String(), k)
		requireAbsent(t, "audit", d.audit.dump(), k)
	}
	if !strings.Contains(d.audit.dump(), `"caller_kind":"agent"`) || !strings.Contains(d.audit.dump(), `"input_sha256"`) {
		t.Fatal("audit is missing caller kind or input digest")
	}
}

func TestKeyReplyOnTheWireCarriesNoKey(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	keyPEM := pemOf(t, edPriv)
	d := startKeyDaemon(t, keySeed, memoryKeys{"ed": keyPEM, "hmac": []byte("h"), "es": nil, "aes": bytes.Repeat([]byte{1}, 32)})

	for _, req := range []KeyRequest{
		{Action: "sign", Connection: "app-local", Field: "RELEASE_KEY", Input: []byte("m")},
		{Action: "sign", Connection: "app-local", Field: "RELEASE_KEY", Alg: "HS512", Input: []byte("m")},
		{Action: "sign", Connection: "missing", Input: []byte("m")},
		{Action: "export", Connection: "app-local", Field: "RELEASE_KEY"},
	} {
		conn, err := net.Dial("unix", d.socket)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeFrame(conn, Request{Op: OpKey, Key: &req}); err != nil {
			t.Fatal(err)
		}
		raw, err := bufio.NewReader(conn).ReadBytes('\n')
		_ = conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		requireAbsent(t, "socket reply", string(raw), keyPEM)
	}
}

func TestKeyPolicyThroughDaemon(t *testing.T) {
	d := startKeyDaemon(t, nil, memoryKeys{})
	presencetest.Approve(t)
	agentEnv := map[string]string{"KEYLATCH_AGENT_SESSION": "1"}
	for k, v := range d.env {
		agentEnv[k] = v
	}

	code, _, errOut := runKeyCLI(t, d.env, "", "key", "allow", "ci", "--field", "SIGNING", "--secret", "default/ci/signing",
		"--op", "sign,jwt-sign", "--alg", "Ed25519", "--ssh-agent", "--host-key", "SHA256:abc")
	if code != 0 {
		t.Fatalf("human allow: exit %d %s", code, errOut)
	}
	code, out, _ := runKeyCLI(t, d.env, "", "key", "list")
	if code != 0 || !strings.Contains(out, "default/ci/signing") || !strings.Contains(out, "jwt_sign") || !strings.Contains(out, "SHA256:abc") {
		t.Fatalf("human list: %d %s", code, out)
	}

	code, _, errOut = runKeyCLI(t, agentEnv, "", "key", "allow", "ci", "--field", "SIGNING", "--op", "decrypt", "--agent-decrypt")
	if code != 2 || !strings.Contains(errOut, "not available to agent callers") {
		t.Fatalf("agent allow: exit %d %s", code, errOut)
	}
	code, out, _ = runKeyCLI(t, agentEnv, "", "key", "list", "ci")
	if code != 0 || strings.Contains(out, "default/ci/signing") || !strings.Contains(out, "SIGNING") {
		t.Fatalf("agent list: %d %s", code, out)
	}

	if code, _, errOut = runKeyCLI(t, agentEnv, "", "key", "revoke", "ci", "--field", "SIGNING", "--op", "jwt-sign", "--ssh-agent"); code != 0 {
		t.Fatalf("agent revoke: exit %d %s", code, errOut)
	}
	_, out, _ = runKeyCLI(t, d.env, "", "key", "list", "ci")
	if strings.Contains(out, "jwt_sign") || strings.Contains(out, "ssh_agent") || !strings.Contains(out, `"sign"`) {
		t.Fatalf("revoke did not narrow: %s", out)
	}
	if code, _, _ = runKeyCLI(t, agentEnv, "", "key", "revoke", "ci"); code != 0 {
		t.Fatalf("agent revoke of the connection: %d", code)
	}
	if code, _, _ = runKeyCLI(t, agentEnv, "", "key", "revoke", "ci"); code != 3 {
		t.Fatalf("revoke of a missing connection: %d", code)
	}

	dump := d.audit.dump()
	for _, want := range []string{`"change":"allow"`, `"change":"revoke"`, `"outcome":"denied"`, `"caller_kind":"agent"`, `"before":"absent"`} {
		if !strings.Contains(dump, want) {
			t.Errorf("audit is missing %s: %s", want, dump)
		}
	}
	for _, args := range [][]string{{"key", "allow"}, {"key", "allow", "c", "--bogus"}, {"key", "revoke", "a", "b"}, {"key", "allow", "c", "--op"}} {
		if code, _, _ := runKeyCLI(t, d.env, "", args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

func TestKeyOperationsDisabledWithoutService(t *testing.T) {
	_, env := startDaemon(t, "")
	code, _, errOut := runKeyCLI(t, env, "x", "key", "sign", "app-local")
	if code != 4 || !strings.Contains(errOut, "not enabled") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if code, _, _ = runKeyCLI(t, env, "", "key", "list"); code != 4 {
		t.Fatalf("list without the service: exit %d", code)
	}
}

func TestKeyArgsRejectBadUsage(t *testing.T) {
	d := startKeyDaemon(t, keySeed, memoryKeys{})
	for _, args := range [][]string{
		{"key"},
		{"key", "export", "app-local"},
		{"key", "sign"},
		{"key", "sign", "a", "b"},
		{"key", "sign", "a", "--bogus", "x"},
		{"key", "sign", "a", "--encoding", "rot13"},
		{"key", "verify", "a"},
		{"key", "sign", "a", "--field"},
	} {
		if code, _, _ := runKeyCLI(t, d.env, "", args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

func dialAgent(t *testing.T, d *keyDaemon) agent.ExtendedAgent {
	t.Helper()
	conn, err := net.Dial("unix", d.agentSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agent.NewClient(conn)
}

func TestSSHAgentEndpointSigns(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPEM := pemOf(t, priv)
	d := startKeyDaemon(t, keySeed, memoryKeys{"ed": keyPEM})
	client := dialAgent(t, d)

	listed, err := client.List()
	if err != nil || len(listed) != 1 {
		t.Fatalf("list: %v %v", listed, err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	if !bytes.Equal(listed[0].Blob, sshPub.Marshal()) {
		t.Fatal("agent lists another key")
	}
	data := []byte("signed through the agent")
	sig, err := client.Sign(sshPub, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshPub.Verify(data, sig); err != nil {
		t.Fatalf("x/crypto verification: %v", err)
	}
	requireAbsent(t, "audit", d.audit.dump(), keyPEM)
	if !strings.Contains(d.audit.dump(), `"operation":"ssh_sign"`) {
		t.Fatal("ssh signing is not audited")
	}
}

func TestSSHAgentShutdownClosesIdleClients(t *testing.T) {
	t.Run("ssh", func(t *testing.T) { testKeyAgentShutdown(t, false) })
	t.Run("gpg", func(t *testing.T) { testKeyAgentShutdown(t, true) })
}

func testKeyAgentShutdown(t *testing.T, gpg bool) {
	t.Helper()
	dir, err := os.MkdirTemp("", "klidle")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	store := keyops.NewStore(filepath.Join(dir, "keys.json"), bytes.Repeat([]byte{3}, 32))
	svc, err := keyops.New(store, memoryKeys{}, &recordedAudit{})
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{Keys: svc})
	ln, err := Listen(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		if gpg {
			done <- srv.ServeGPGAgent(ctx, ln)
		} else {
			done <- srv.ServeSSHAgent(ctx, ln)
		}
	}()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: ln.Addr().String(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if gpg {
		if line, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.HasPrefix(line, "OK ") {
			t.Fatalf("GnuPG greeting: %q, %v", line, err)
		}
	} else {
		if _, err := agent.NewClient(conn).List(); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle agent client blocked daemon shutdown")
	}
}

func TestSSHAgentWithSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := startKeyDaemon(t, keySeed, memoryKeys{"ed": pemOf(t, priv)})
	sshPub, _ := ssh.NewPublicKey(pub)

	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	_ = os.MkdirAll(home, 0o700)
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	pubFile := filepath.Join(dir, "key.pub")
	allowed := filepath.Join(dir, "allowed_signers")
	data := filepath.Join(dir, "data.txt")
	_ = os.WriteFile(pubFile, []byte(authorized+"\n"), 0o600)
	_ = os.WriteFile(allowed, []byte("release@example "+authorized+"\n"), 0o600)
	_ = os.WriteFile(data, []byte("payload"), 0o600)

	run := func(stdin string, args ...string) error {
		cmd := exec.Command("ssh-keygen", args...)
		cmd.Env = []string{"HOME=" + home, "SSH_AUTH_SOCK=" + d.agentSocket, "PATH=" + os.Getenv("PATH")}
		cmd.Stdin = strings.NewReader(stdin)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w: %s", err, out)
		}
		return nil
	}
	if err := run("", "-Y", "sign", "-f", pubFile, "-n", "file", data); err != nil {
		t.Fatalf("ssh-keygen -Y sign through the agent: %v", err)
	}
	if err := run("payload", "-Y", "verify", "-f", allowed, "-I", "release@example", "-n", "file", "-s", data+".sig"); err != nil {
		t.Fatalf("ssh-keygen -Y verify: %v", err)
	}
	if err := run("other payload", "-Y", "verify", "-f", allowed, "-I", "release@example", "-n", "file", "-s", data+".sig"); err == nil {
		t.Fatal("ssh-keygen verified a different payload")
	}
}

func TestGitCommitSigningThroughSSHAgent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyPEM := pemOf(t, priv)
	d := startKeyDaemon(t, keySeed, memoryKeys{"ed": keyPEM})
	sshPub, _ := ssh.NewPublicKey(pub)

	dir := t.TempDir()
	home, repo := filepath.Join(dir, "home"), filepath.Join(dir, "repo")
	for _, p := range []string{home, repo} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	pubFile, allowed := filepath.Join(dir, "signing.pub"), filepath.Join(dir, "allowed_signers")
	_ = os.WriteFile(pubFile, []byte(authorized+"\n"), 0o600)
	_ = os.WriteFile(allowed, []byte("dev@example.com "+authorized+"\n"), 0o600)

	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = []string{
			"HOME=" + home, "PATH=" + os.Getenv("PATH"), "SSH_AUTH_SOCK=" + d.agentSocket,
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Dev"},
		{"config", "user.email", "dev@example.com"},
		{"config", "gpg.format", "ssh"},
		{"config", "user.signingkey", pubFile},
		{"config", "gpg.ssh.allowedSignersFile", allowed},
	} {
		if out, err := git(args...); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if out, err := git("commit", "-q", "--allow-empty", "-S", "-m", "signed through the keylatch agent"); err != nil {
		t.Fatalf("signing a commit through the agent: %v %s", err, out)
	}
	if out, err := git("verify-commit", "HEAD"); err != nil {
		t.Fatalf("verify-commit: %v %s", err, out)
	}
	if out, err := git("log", "-1", "--format=%G?"); err != nil || strings.TrimSpace(out) != "G" {
		t.Fatalf("signature status %q: %v", out, err)
	}
	requireAbsent(t, "audit", d.audit.dump(), keyPEM)
	if !strings.Contains(d.audit.dump(), `"operation":"ssh_sign"`) {
		t.Fatal("commit signing is not audited")
	}
}
