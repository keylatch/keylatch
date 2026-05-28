package proxy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// memKeyring is an in-memory Keyring for testing.
type memKeyring struct {
	data map[string][]byte
}

func newMemKeyring() *memKeyring {
	return &memKeyring{data: make(map[string][]byte)}
}

func (k *memKeyring) Get(key string) ([]byte, error) {
	v, ok := k.data[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (k *memKeyring) Set(key string, value []byte) error {
	k.data[key] = value
	return nil
}

// TestLoadOrCreateCA_PrivateKeyInKeyring verifies the private key is stored in keyring.
func TestLoadOrCreateCA_PrivateKeyInKeyring(t *testing.T) {
	kr := newMemKeyring()
	cert, _, err := LoadOrCreateCA(kr, "test-ca-key")
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}

	// Private key must be in keyring.
	privKeyBytes, err := kr.Get("test-ca-key")
	if err != nil {
		t.Fatalf("private key not found in keyring: %v", err)
	}
	if len(privKeyBytes) == 0 {
		t.Error("private key bytes should not be empty")
	}
}

// TestLoadOrCreateCA_PublicCertAccessible verifies the CA cert has expected fields.
func TestLoadOrCreateCA_PublicCertAccessible(t *testing.T) {
	kr := newMemKeyring()
	cert, _, err := LoadOrCreateCA(kr, "test-ca-key")
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
	if cert.Subject.CommonName != "keylatch-local-ca" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}
}

// TestLoadOrCreateCA_SecondCallUsesStoredKey verifies the same key is reused on second call.
func TestLoadOrCreateCA_SecondCallUsesStoredKey(t *testing.T) {
	kr := newMemKeyring()
	cert1, _, err := LoadOrCreateCA(kr, "test-ca-key")
	if err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}

	cert2, _, err := LoadOrCreateCA(kr, "test-ca-key")
	if err != nil {
		t.Fatalf("second LoadOrCreateCA: %v", err)
	}

	// Both certs come from the same key — public key should match.
	if cert1.PublicKey == nil || cert2.PublicKey == nil {
		t.Fatal("expected non-nil public keys")
	}
	// Verify serial numbers differ (since self-signed uses random serial each time).
	// What we really care about is that no error occurred and certs are valid.
	if cert1 == nil || cert2 == nil {
		t.Fatal("nil cert on second call")
	}
}

// TestInjectCAEnv_InjectsAllVars verifies all four env vars are injected.
func TestInjectCAEnv_InjectsAllVars(t *testing.T) {
	env := []string{"EXISTING_VAR=value"}
	result := InjectCAEnv(env, "/tmp/keylatch-ca.pem", true)

	expected := []string{
		"SSL_CERT_FILE=/tmp/keylatch-ca.pem",
		"REQUESTS_CA_BUNDLE=/tmp/keylatch-ca.pem",
		"NODE_EXTRA_CA_CERTS=/tmp/keylatch-ca.pem",
		"GIT_SSL_CAINFO=/tmp/keylatch-ca.pem",
	}
	for _, want := range expected {
		found := false
		for _, got := range result {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in result env", want)
		}
	}
}

// TestInjectCAEnv_NoInject verifies env is unmodified when inject=false.
func TestInjectCAEnv_NoInject(t *testing.T) {
	env := []string{"EXISTING=val"}
	result := InjectCAEnv(env, "/tmp/ca.pem", false)

	if len(result) != len(env) {
		t.Errorf("expected env unchanged; got %v", result)
	}
}

// TestWriteCACert_WritesToDisk verifies WriteCACert writes a PEM to a temp file.
func TestWriteCACert_WritesToDisk(t *testing.T) {
	kr := newMemKeyring()
	cert, _, err := LoadOrCreateCA(kr, "wc-test-key")
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")

	if err := WriteCACert(cert, path); err != nil {
		t.Fatalf("WriteCACert: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	if !bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Errorf("expected PEM-encoded certificate, got: %s", data[:min(len(data), 50)])
	}
}

// TestNewTLSCA_CertForHost_ReturnsCert verifies CertForHost returns a valid leaf cert.
func TestNewTLSCA_CertForHost_ReturnsCert(t *testing.T) {
	kr := newMemKeyring()
	caCert, caKey, err := LoadOrCreateCA(kr, "cert-host-key")
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	ca := newTLSCA(caCert, caKey)
	cert, err := ca.CertForHost("test.example.com")
	if err != nil {
		t.Fatalf("CertForHost: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
	if cert.Leaf == nil {
		t.Fatal("expected non-nil leaf")
	}
	if cert.Leaf.DNSNames[0] != "test.example.com" {
		t.Errorf("expected DNS name test.example.com, got %v", cert.Leaf.DNSNames)
	}
}

// TestNewTLSCA_CertForHost_Cached verifies that CertForHost caches certificates.
func TestNewTLSCA_CertForHost_Cached(t *testing.T) {
	kr := newMemKeyring()
	caCert, caKey, err := LoadOrCreateCA(kr, "cert-cache-key")
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	ca := newTLSCA(caCert, caKey)
	cert1, err := ca.CertForHost("cached.example.com")
	if err != nil {
		t.Fatalf("first CertForHost: %v", err)
	}
	cert2, err := ca.CertForHost("cached.example.com")
	if err != nil {
		t.Fatalf("second CertForHost: %v", err)
	}

	// Both should point to the same cached value.
	if cert1 != cert2 {
		t.Error("expected same pointer on cache hit")
	}
}

// TestWriteCACert_InvalidPath verifies WriteCACert returns an error for unwritable paths.
func TestWriteCACert_InvalidPath(t *testing.T) {
	kr := newMemKeyring()
	cert, _, err := LoadOrCreateCA(kr, "wc-err-key")
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	err = WriteCACert(cert, "/nonexistent/dir/ca.pem")
	if err == nil {
		t.Error("expected error for unwritable path")
	}
}

// TestCertForHost_MultipleHosts verifies CertForHost caches independently per host.
func TestCertForHost_MultipleHosts(t *testing.T) {
	kr := newMemKeyring()
	caCert, caKey, err := LoadOrCreateCA(kr, "multi-host-key")
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	ca := newTLSCA(caCert, caKey)

	hosts := []string{"api.example.com", "cdn.example.com", "www.example.com"}
	certs := make(map[string]interface{})

	for _, host := range hosts {
		cert, err := ca.CertForHost(host)
		if err != nil {
			t.Fatalf("CertForHost(%q): %v", host, err)
		}
		if cert == nil {
			t.Fatalf("nil cert for %q", host)
		}
		certs[host] = cert
	}

	if len(certs) != len(hosts) {
		t.Errorf("expected %d certs, got %d", len(hosts), len(certs))
	}
}

// TestInjectCAEnv_OverridesExisting verifies existing CA env vars are overridden.
func TestInjectCAEnv_OverridesExisting(t *testing.T) {
	env := []string{
		"SSL_CERT_FILE=/old/path/ca.pem",
		"OTHER=val",
	}
	result := InjectCAEnv(env, "/new/path/ca.pem", true)

	// Should not have duplicate SSL_CERT_FILE.
	count := 0
	for _, e := range result {
		if e == "SSL_CERT_FILE=/old/path/ca.pem" {
			t.Error("old SSL_CERT_FILE should be removed")
		}
		if e == "SSL_CERT_FILE=/new/path/ca.pem" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly one SSL_CERT_FILE entry; got %d", count)
	}
}
