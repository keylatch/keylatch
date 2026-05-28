package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// tlsCA holds a CA certificate and key used to mint per-host leaf certificates
// for HTTPS CONNECT interception.
type tlsCA struct {
	cert  *x509.Certificate
	key   crypto.PrivateKey
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// newTLSCA wraps an existing CA cert+key into a tlsCA.
func newTLSCA(cert *x509.Certificate, key crypto.PrivateKey) *tlsCA {
	return &tlsCA{
		cert:  cert,
		key:   key,
		cache: make(map[string]*tls.Certificate),
	}
}

// CertForHost returns (or creates) a TLS leaf certificate for host, signed by
// the CA. Certificates are cached per hostname to avoid repeated signing.
func (ca *tlsCA) CertForHost(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if cert, ok := ca.cache[host]; ok {
		// Serve cached cert only if it has not expired.
		if cert.Leaf != nil && time.Now().Before(cert.Leaf.NotAfter) {
			return cert, nil
		}
		delete(ca.cache, host)
	}

	// Generate a new ephemeral ECDSA key for the leaf.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proxy_ca: generate leaf key for %q: %w", host, err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("proxy_ca: generate serial for %q: %w", host, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:    []string{host},
		NotBefore:   time.Now().Add(-1 * time.Minute),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	ecKey, ok := ca.key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("proxy_ca: CA private key must be *ecdsa.PrivateKey")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ecKey)
	if err != nil {
		return nil, fmt.Errorf("proxy_ca: sign leaf cert for %q: %w", host, err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("proxy_ca: parse leaf cert for %q: %w", host, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}

	// S4: cap cache size to prevent unbounded growth from many distinct hostnames.
	// If the cache has grown beyond 1000 entries, flush it entirely before inserting.
	if len(ca.cache) > 1000 {
		ca.cache = make(map[string]*tls.Certificate)
	}
	ca.cache[host] = tlsCert
	return tlsCert, nil
}
