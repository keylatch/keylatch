//go:build unix

package brokerd

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // GnuPG public-key identifier only.
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/control"
)

func TestBrokerGPGAgentUsesIdentifiedPartition(t *testing.T) {
	h := newHarness(t, nil)
	p, err := h.srv.partition(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := p.store.Put(t.Context(), "keys/gpg", private); err != nil {
		t.Fatal(err)
	}
	allow := control.Request{Op: control.OpKeyPolicy, KeyPolicy: &control.KeyPolicyRequest{Action: "allow", Connection: "release", Field: "key", Secret: "keys/gpg", Operations: []string{"gpg_sign"}, Algorithms: []string{"RS256"}}}
	if response := controlKeyRequest(t, p, peerAs(1000, ""), allow); !response.OK {
		t.Fatalf("allow: %+v", response)
	}
	grip := sha1.Sum(append([]byte{0}, key.N.Bytes()...)) //nolint:gosec // Protocol keygrip only.
	digest := sha256.Sum256([]byte("partition signing request"))
	for _, tc := range []struct {
		name    string
		uid     uint32
		corrupt bool
	}{
		{"owner", 1000, false}, {"other user", 1001, false}, {"service account", 33, false}, {"corrupt policy", 1000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.corrupt {
				if err := os.WriteFile(filepath.Join(p.policy.Dir, "policy.json"), []byte(`{"default_deny":false}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			h.srv.cfg.Identify = func(control.Conn) (*Identity, error) {
				return &Identity{UID: tc.uid, PID: 4242, Start: "9999", pin: okPin{}}, nil
			}
			server, client := pair(t)
			done := make(chan struct{})
			go func() { defer close(done); defer func() { _ = server.Close() }(); h.srv.handle(t.Context(), server) }()
			defer func() { _ = client.Close(); <-done }()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			if err := json.NewEncoder(client).Encode(control.Request{Op: control.OpKeyAgent, KeyAgent: "gpg"}); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(client)
			line, err := reader.ReadBytes('\n')
			if err != nil {
				t.Fatal(err)
			}
			var response control.Response
			if err := json.Unmarshal(line, &response); err != nil {
				t.Fatal(err)
			}
			if tc.corrupt || tc.uid == 33 {
				if response.OK {
					t.Fatal("unauthorized stream admitted")
				}
				return
			}
			if !response.OK {
				t.Fatalf("stream: %+v", response)
			}
			if tc.uid == 1000 {
				_, _ = fmt.Fprintf(client, "SIGKEY %X\nSETHASH 8 %x\nPKSIGN\n", grip, digest)
				var result strings.Builder
				for replies := 0; replies < 4; {
					line, err := reader.ReadString('\n')
					if err != nil {
						t.Fatal(err)
					}
					result.WriteString(line)
					if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "ERR") {
						replies++
					}
				}
				if strings.Contains(result.String(), "ERR ") || !strings.Contains(result.String(), "D ") {
					t.Fatalf("owner signing refused: %s", result.String())
				}
				if strings.Contains(result.String(), string(private)) {
					t.Fatal("private key escaped into protocol")
				}
				if err := os.WriteFile(filepath.Join(p.policy.Dir, "policy.json"), []byte(`{"default_deny":false}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, _ = fmt.Fprintf(client, "SIGKEY %X\nSETHASH 8 %x\nPKSIGN\nBYE\n", grip, digest)
			out, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(out), "ERR ") || strings.Contains(string(out), "D ") {
				t.Fatalf("unapproved key operation succeeded: %s", out)
			}
			if bytes.Contains(out, private) || bytes.Contains(out, der) {
				t.Fatal("private key escaped into protocol")
			}
		})
	}
}
