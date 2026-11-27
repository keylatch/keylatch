package placeholder

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// sessionCA is a certificate authority that lives for one session. Its Name
// Constraints limit it to the session's hosts, so a client that trusts it
// gains nothing against any other site even if the key were extracted.
type sessionCA struct {
	cert      *x509.Certificate
	key       *ecdsa.PrivateKey
	pem       []byte
	permitted []string

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

var errNotPermitted = errors.New("placeholder: host is outside the session CA's name constraints")

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// constraintFor turns a binding host pattern into a DNS name constraint: a
// leading wildcard becomes a subdomain-only constraint.
func constraintFor(pattern string) string {
	host := strings.ToLower(pattern)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if rest, ok := strings.CutPrefix(host, "*."); ok {
		return "." + rest
	}
	return host
}

func newSessionCA(id string, hosts []string, ttl time.Duration) (*sessionCA, error) {
	var permitted []string
	seen := map[string]bool{}
	for _, h := range hosts {
		if c := constraintFor(h); !seen[c] {
			seen[c] = true
			permitted = append(permitted, c)
		}
	}
	if len(permitted) == 0 {
		return nil, errors.New("placeholder: a session CA needs at least one host")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("placeholder: CA key: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	_, anyV4, _ := net.ParseCIDR("0.0.0.0/0")
	_, anyV6, _ := net.ParseCIDR("::/0")
	tmpl := &x509.Certificate{
		SerialNumber:                sn,
		Subject:                     pkix.Name{Organization: []string{"Keylatch"}, CommonName: "Keylatch session " + id[:8]},
		NotBefore:                   time.Now().Add(-time.Minute),
		NotAfter:                    time.Now().Add(ttl + time.Minute),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
		ExcludedIPRanges:            []*net.IPNet{anyV4, anyV6},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("placeholder: CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("placeholder: parse CA certificate: %w", err)
	}
	return &sessionCA{
		cert:      cert,
		key:       key,
		pem:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		permitted: permitted,
		leaves:    map[string]*tls.Certificate{},
	}, nil
}

func (c *sessionCA) permits(host string) bool {
	host = strings.ToLower(host)
	for _, p := range c.permitted {
		if rest, sub := strings.CutPrefix(p, "."); sub {
			if strings.HasSuffix(host, "."+rest) {
				return true
			}
			continue
		}
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

// leaf returns the server certificate for host, issuing it on first use.
func (c *sessionCA) leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(host)
	if !c.permits(host) {
		return nil, errNotPermitted
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key == nil {
		return nil, errors.New("placeholder: session CA is closed")
	}
	if l, ok := c.leaves[host]; ok {
		return l, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("placeholder: leaf key: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     c.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("placeholder: leaf certificate: %w", err)
	}
	l := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}
	c.leaves[host] = l
	return l, nil
}

func (c *sessionCA) wipe() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaves = map[string]*tls.Certificate{}
	c.key = nil
}
