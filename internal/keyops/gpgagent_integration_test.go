//go:build unix

package keyops

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // OpenPGP v4 public-key fingerprints use SHA-1.
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pgpPacket(tag byte, body []byte) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{0xc0 | tag, 255}, uint32(len(body))), body...)
}

func selfSignedPublicRSA(t *testing.T, key *rsa.PrivateKey) ([]byte, string) {
	t.Helper()
	public := pgpPublicPacket(&key.PublicKey)
	body := public[6:]
	keyHashInput := append(binary.BigEndian.AppendUint16([]byte{0x99}, uint16(len(body))), body...)
	fingerprint := sha1.Sum(keyHashInput) //nolint:gosec // OpenPGP v4 public identifier only.
	uid := []byte("Keylatch test <keylatch@example.invalid>")
	header := []byte{4, 0x13, 1, 8, 0, 6, 5, 2, 0x65, 0x53, 0xf1, 0}
	toHash := append([]byte(nil), keyHashInput...)
	toHash = binary.BigEndian.AppendUint32(append(toHash, 0xb4), uint32(len(uid)))
	toHash = append(toHash, uid...)
	toHash = append(toHash, header...)
	toHash = binary.BigEndian.AppendUint32(append(toHash, 4, 0xff), uint32(len(header)))
	digest := sha256.Sum256(toHash)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	cert := append(append([]byte(nil), header...), 0, 10, 9, 16)
	cert = append(cert, fingerprint[12:]...)
	cert = append(append(cert, digest[:2]...), pgpMPI(sig)...)
	return append(append(public, pgpPacket(13, uid)...), pgpPacket(2, cert)...), fmt.Sprintf("%X", fingerprint)
}

func TestGPGDetachedSignatureUsesDaemonKey(t *testing.T) {
	bin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("GnuPG is not installed")
	}
	keys := newTestKeys(t)
	private, err := parsePrivateKey(keys.rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroSigner(private)
	pub, fingerprint := selfSignedPublicRSA(t, private.(*rsa.PrivateKey))
	dir, err := os.MkdirTemp("", "klpgp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	configBin, err := exec.LookPath("gpgconf")
	if err != nil {
		t.Skip("gpgconf is not installed")
	}
	if out, err := exec.CommandContext(ctx, configBin, "--homedir", dir, "--create-socketdir").CombinedOutput(); err != nil {
		t.Fatalf("private socket directory: %v: %s", err, out)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanup, configBin, "--homedir", dir, "--remove-socketdir").Run()
	}()
	socketInfo, err := exec.CommandContext(ctx, configBin, "--homedir", dir, "--list-dirs", "agent-socket").Output()
	if err != nil {
		t.Fatal(err)
	}
	socketPath := strings.TrimSpace(string(socketInfo))
	if filepath.Dir(socketPath) != dir && !strings.HasPrefix(filepath.Base(filepath.Dir(socketPath)), "d.") {
		t.Fatalf("unexpected non-private GnuPG socket: %s", socketPath)
	}
	base := []string{"--no-options", "--homedir", dir, "--no-autostart", "--batch"}
	imp := exec.CommandContext(ctx, bin, append(base, "--import")...)
	imp.Stdin = bytes.NewReader(pub)
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("import public fixture: %v: %s", err, out)
	}
	list := exec.CommandContext(ctx, bin, append(base, "--with-colons", "--list-keys", fingerprint)...)
	if out, err := list.CombinedOutput(); err != nil || !bytes.Contains(out, []byte(fingerprint)) {
		t.Fatalf("public fixture missing: %v: %s", err, out)
	}
	svc, audit := service(t, fullPolicy("key", []string{string(OpGPGSign)}, RS256), mapKeys{"key": keys.rsaKey})
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	tracePath := filepath.Join(dir, "assuan-requests.log")
	trace, err := os.OpenFile(tracePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = trace.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			_ = svc.ServeGPGAgent(ctx, assuanIO{io.TeeReader(conn, trace), conn}, Caller{Kind: "agent", Constrained: true})
			stop()
			_ = conn.Close()
		}
	}()
	defer func() { cancel(); _ = listener.Close(); <-done }()
	message := []byte("a detached signature without a private key in GnuPG's home\n")
	sign := exec.CommandContext(ctx, bin, append(base, "--debug", "ipc", "--verbose", "--digest-algo", "SHA256", "--local-user", fingerprint, "--output", "-", "--detach-sign")...)
	sign.Stdin = bytes.NewReader(message)
	var stderr bytes.Buffer
	sign.Stderr = &stderr
	signature, err := sign.Output()
	if err != nil {
		requests, _ := os.ReadFile(tracePath)
		t.Fatalf("gpg signing: %v: %s\nrequests: %s\nlistener: %s; discovered: %s", err, stderr.String(), requests, listener.Addr(), socketInfo)
	}
	messagePath, sigPath := filepath.Join(dir, "message"), filepath.Join(dir, "message.sig")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	verify := exec.CommandContext(ctx, bin, append(base, "--verify", sigPath, messagePath)...)
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("gpg verification: %v: %s", err, out)
	}
	assertAbsent(t, string(signature), keys.rsaKey)
	assertAbsent(t, audit.dump(), keys.rsaKey)
}

func TestGPGConnectAgentSignsThroughSocket(t *testing.T) {
	bin, err := exec.LookPath("gpg-connect-agent")
	if err != nil {
		t.Skip("gpg-connect-agent is not installed")
	}
	keys := newTestKeys(t)
	private, err := parsePrivateKey(keys.rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroSigner(private)
	grip, _, err := gpgPublic(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	svc, audit := service(t, fullPolicy("key", []string{string(OpGPGSign)}, RS256), mapKeys{"key": keys.rsaKey})
	dir, err := os.MkdirTemp("", "klgpg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "S.gpg-agent")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		done <- svc.ServeGPGAgent(ctx, conn, Caller{Kind: "agent", Constrained: true})
	}()
	digest := sha256.Sum256([]byte("real GnuPG Assuan client"))
	cmd := exec.CommandContext(ctx, bin, "--homedir", dir, "--no-autostart", "--raw-socket", path, "HAVEKEY "+grip, "SIGKEY "+grip, fmt.Sprintf("SETHASH 8 %x", digest), "PKSIGN", "/bye")
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "ERR ") {
		t.Fatalf("GnuPG client: %v: %s", err, out)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sig := signaturePart(t, assuanData(t, string(out)), "s")
	if err := rsa.VerifyPKCS1v15(private.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, string(out), keys.rsaKey)
	assertAbsent(t, audit.dump(), keys.rsaKey)
}
