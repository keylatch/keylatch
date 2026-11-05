package keyops

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
)

type mapKeys map[string][]byte

func (m mapKeys) Fetch(_ context.Context, secret string) ([]byte, error) {
	v, ok := m[secret]
	if !ok {
		return nil, fmt.Errorf("%w: missing", ErrNotFound)
	}
	return append([]byte(nil), v...), nil
}

type captureAudit struct {
	mu     sync.Mutex
	events []audit.Event
	fail   bool
}

func (c *captureAudit) Emit(_ context.Context, e audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return fmt.Errorf("disk full")
	}
	c.events = append(c.events, e)
	return nil
}

func (c *captureAudit) dump() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := json.Marshal(c.events)
	return string(b)
}

type staticPolicy struct {
	conns map[string]map[string]FieldPolicy
}

func (p staticPolicy) Lookup(connection, field string) (KeyRef, error) {
	fields, ok := p.conns[connection]
	if !ok {
		return KeyRef{}, fmt.Errorf("%w: connection", ErrNotFound)
	}
	if field == "" && len(fields) == 1 {
		for f := range fields {
			field = f
		}
	}
	fp, ok := fields[field]
	if !ok {
		return KeyRef{}, fmt.Errorf("%w: field", ErrNotFound)
	}
	return KeyRef{Connection: connection, Field: field, Policy: fp}, nil
}

func (p staticPolicy) SSHKeys() ([]KeyRef, error) {
	var out []KeyRef
	for c, fields := range p.conns {
		for f, fp := range fields {
			if fp.SSHAgent != nil {
				out = append(out, KeyRef{Connection: c, Field: f, Policy: fp})
			}
		}
	}
	return out, nil
}

func (p staticPolicy) GPGKeys() ([]KeyRef, error) {
	var out []KeyRef
	for c, fields := range p.conns {
		for f, fp := range fields {
			for _, op := range fp.Operations {
				if op == string(OpGPGSign) {
					out = append(out, KeyRef{Connection: c, Field: f, Policy: fp})
					break
				}
			}
		}
	}
	return out, nil
}

func pkcs8PEM(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

type testKeys struct {
	ed, es256, es384, rsaKey []byte
	edPub                    ed25519.PublicKey
	es256Pub                 *ecdsa.PublicKey
	hmac                     []byte
	aes                      []byte
}

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sec1, _ := x509.MarshalECPrivateKey(p384)
	h := make([]byte, 48)
	a := make([]byte, 32)
	_, _ = rand.Read(h)
	_, _ = rand.Read(a)
	return testKeys{
		ed:       pkcs8PEM(t, edPriv),
		es256:    pkcs8PEM(t, p256),
		es384:    pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		rsaKey:   pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}),
		edPub:    edPub,
		es256Pub: &p256.PublicKey,
		hmac:     h,
		aes:      a,
	}
}

// encodings lists every textual form a key could leak in.
func encodings(b []byte) []string {
	out := []string{
		string(b),
		hex.EncodeToString(b),
		strings.ToUpper(hex.EncodeToString(b)),
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
	}
	if blk, _ := pem.Decode(b); blk != nil {
		out = append(out,
			base64.StdEncoding.EncodeToString(blk.Bytes),
			base64.RawURLEncoding.EncodeToString(blk.Bytes),
			hex.EncodeToString(blk.Bytes),
		)
		if len(blk.Bytes) > 48 {
			tail := blk.Bytes[len(blk.Bytes)-32:]
			out = append(out, string(tail), hex.EncodeToString(tail), base64.StdEncoding.EncodeToString(tail))
		}
	}
	return out
}

func assertAbsent(t *testing.T, haystack string, keys ...[]byte) {
	t.Helper()
	for _, k := range keys {
		for _, enc := range encodings(k) {
			if len(enc) >= 16 && strings.Contains(haystack, enc) {
				t.Fatalf("key material found in captured output (%d-char form)", len(enc))
			}
		}
	}
}

func fullPolicy(secret string, ops []string, algs ...string) staticPolicy {
	return staticPolicy{conns: map[string]map[string]FieldPolicy{
		"app-local": {"KEY": {Secret: secret, Operations: ops, Algorithms: algs}},
	}}
}
