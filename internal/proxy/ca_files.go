package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"time"
)

// CA is the certificate authority the proxy signs per-host leaf certificates with.
type CA = tlsCA

const fileCAValidity = 10 * 365 * 24 * time.Hour

// LoadOrCreateFileCA loads the CA from certPath and keyPath, creating both on
// first use (key mode 0600, certificate 0644). It exists for an unattended
// service that has no OS keyring. The certificate is name-constrained to
// permittedDNS (and their subdomains): a guest that trusts it trusts it for
// those names only, and a leaked key cannot impersonate any other host.
func LoadOrCreateFileCA(certPath, keyPath string, permittedDNS []string) (*CA, error) {
	if len(permittedDNS) == 0 {
		return nil, errors.New("proxy ca: at least one permitted DNS name is required")
	}
	keyPEM, kerr := os.ReadFile(keyPath)
	certPEM, cerr := os.ReadFile(certPath)
	if errors.Is(kerr, os.ErrNotExist) && errors.Is(cerr, os.ErrNotExist) {
		return createFileCA(certPath, keyPath, permittedDNS)
	}
	if kerr != nil || cerr != nil {
		return nil, fmt.Errorf("proxy ca: read %s and %s: key: %v; cert: %v", keyPath, certPath, kerr, cerr)
	}
	kb, _ := pem.Decode(keyPEM)
	cb, _ := pem.Decode(certPEM)
	if kb == nil || cb == nil {
		return nil, errors.New("proxy ca: key or certificate file is not PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("proxy ca: parse key: %w", err)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("proxy ca: parse certificate: %w", err)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("proxy ca: certificate does not belong to the key; remove both files to regenerate (guests must trust the new certificate)")
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("proxy ca: certificate expired %s; remove both files to regenerate (guests must trust the new certificate)", cert.NotAfter.Format(time.DateOnly))
	}
	want := slices.Clone(permittedDNS)
	got := slices.Clone(cert.PermittedDNSDomains)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return nil, fmt.Errorf("proxy ca: certificate is constrained to %v, not %v; remove both files to regenerate", got, want)
	}
	return newTLSCA(cert, key), nil
}

func createFileCA(certPath, keyPath string, permittedDNS []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxy ca: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxy ca: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Keylatch Proxy"},
			CommonName:   "keylatch-proxy-ca",
		},
		NotBefore:                   time.Now().Add(-time.Minute),
		NotAfter:                    time.Now().Add(fileCAValidity),
		IsCA:                        true,
		KeyUsage:                    x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permittedDNS,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("proxy ca: create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("proxy ca: parse certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("proxy ca: marshal key: %w", err)
	}
	// O_EXCL: never overwrite a key another process just created.
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("proxy ca: create key file: %w", err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		_ = kf.Close()
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("proxy ca: write key: %w", err)
	}
	if err := kf.Close(); err != nil {
		return nil, fmt.Errorf("proxy ca: close key file: %w", err)
	}
	if err := WriteCACert(cert, certPath); err != nil {
		_ = os.Remove(keyPath)
		return nil, err
	}
	return newTLSCA(cert, key), nil
}

// CertPEM returns the CA certificate (public part only) as PEM.
func (ca *tlsCA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}
