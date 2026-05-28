package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Keyring is a minimal interface for storing and retrieving private key bytes.
// In production this is backed by the OS keyring (never plaintext file).
type Keyring interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
}

// LoadOrCreateCA loads an existing CA keypair from the keyring or generates a new one.
// The private key is stored in the OS keyring only — NEVER to plaintext file.
// Only the public CA certificate is returned for writing to disk.
//
// Returns (cert, privateKey, error).
func LoadOrCreateCA(keyring Keyring, keyringKey string) (*x509.Certificate, crypto.PrivateKey, error) {
	// Try to load existing private key from keyring.
	privKeyDER, err := keyring.Get(keyringKey)
	if err == nil && len(privKeyDER) > 0 {
		privKey, parseErr := x509.ParseECPrivateKey(privKeyDER)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("tls_ca: parse stored private key: %w", parseErr)
		}
		cert, certErr := selfSignedCACertWithKey(privKey)
		if certErr != nil {
			return nil, nil, fmt.Errorf("tls_ca: regenerate cert from stored key: %w", certErr)
		}
		return cert, privKey, nil
	}

	// Generate new ECDSA P-256 keypair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tls_ca: generate key: %w", err)
	}

	// Encode private key as DER.
	privKeyDER, err = x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tls_ca: marshal private key: %w", err)
	}

	// Store private key in keyring only — NEVER on disk.
	if err := keyring.Set(keyringKey, privKeyDER); err != nil {
		return nil, nil, fmt.Errorf("tls_ca: store private key in keyring: %w", err)
	}

	// Generate self-signed CA certificate.
	cert, err := selfSignedCACertWithKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tls_ca: generate CA cert: %w", err)
	}

	return cert, privKey, nil
}

// WriteCACert writes the CA certificate (public only) to path as PEM.
// The file permissions are 0o644 — public cert only, no secrets.
func WriteCACert(cert *x509.Certificate, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec // G302: CA certificate is a public file (no secrets); 0o644 is correct
	if err != nil {
		return fmt.Errorf("tls_ca: open cert file: %w", err)
	}
	defer f.Close() //nolint:errcheck // defer close of cert file, write error is captured by pem.Encode return
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// selfSignedCACertWithKey generates a self-signed CA certificate signed by privKey.
func selfSignedCACertWithKey(privKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"Keylatch Local CA"},
			OrganizationalUnit: []string{"Phase 13 Proxy"},
			CommonName:         "keylatch-local-ca",
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated certificate: %w", err)
	}
	return cert, nil
}
