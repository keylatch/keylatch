// Package machinecert issues and reads the certificates that remote machines
// present to the broker's machine listener. A certificate names the machine,
// the domain (namespace) it may reach and the capabilities it holds in
// extensions, next to the expiry the certificate already carries. The broker
// signs them with its machine CA; the listener trusts that CA and nothing else.
package machinecert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// The extensions sit under an arc reserved for documentation, since Keylatch
// has no registered arc of its own.
var (
	oidDomain = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	oidCaps   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
	oidExpiry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}
)

// Claims is what a machine certificate says about its holder.
type Claims struct {
	Name     string
	Domain   string
	Caps     []string
	NotAfter time.Time
}

// ErrNoClaims means a certificate carries no machine extensions.
var ErrNoClaims = errors.New("machinecert: the certificate carries no machine claims")

func utf8(s string) ([]byte, error) { return asn1.MarshalWithParams(s, "utf8") }

// CA returns the machine CA certificate for key. The certificate is a pure
// function of the key, so every call yields the same bytes.
func CA(key ed25519.PrivateKey) (*x509.Certificate, []byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Keylatch machine CA"},
		NotBefore:             time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("machinecert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	return cert, der, err
}

// IssueClient signs a client certificate for pub. It is valid from a minute
// ago, to absorb clock skew, until c.NotAfter.
func IssueClient(ca *x509.Certificate, caKey ed25519.PrivateKey, pub ed25519.PublicKey, c Claims, now time.Time) (der []byte, serial *big.Int, err error) {
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	serial.Add(serial, big.NewInt(2))
	domain, err := utf8(c.Domain)
	if err != nil {
		return nil, nil, err
	}
	caps, err := utf8(strings.Join(c.Caps, ","))
	if err != nil {
		return nil, nil, err
	}
	expiry, err := utf8(c.NotAfter.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: c.Name},
		NotBefore:    now.Add(-time.Minute).UTC(),
		NotAfter:     c.NotAfter.UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: oidDomain, Value: domain},
			{Id: oidCaps, Value: caps},
			{Id: oidExpiry, Value: expiry},
		},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	return der, serial, err
}

// IssueServer signs the listener's certificate for pub, valid for hosts (IP
// addresses and names) until notAfter.
func IssueServer(ca *x509.Certificate, caKey ed25519.PrivateKey, pub ed25519.PublicKey, hosts []string, now, notAfter time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(2)),
		Subject:      pkix.Name{CommonName: "keylatch machine listener"},
		NotBefore:    now.Add(-time.Minute).UTC(),
		NotAfter:     notAfter.UTC(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
}

// ClaimsOf reads the machine claims of a certificate whose chain the caller
// has already verified.
func ClaimsOf(cert *x509.Certificate) (Claims, error) {
	c := Claims{Name: cert.Subject.CommonName, NotAfter: cert.NotAfter}
	var haveDomain, haveCaps bool
	for _, e := range cert.Extensions {
		var s string
		switch {
		case e.Id.Equal(oidDomain), e.Id.Equal(oidCaps), e.Id.Equal(oidExpiry):
			if rest, err := asn1.UnmarshalWithParams(e.Value, &s, "utf8"); err != nil || len(rest) != 0 {
				return Claims{}, fmt.Errorf("machinecert: malformed extension %s", e.Id)
			}
		default:
			continue
		}
		switch {
		case e.Id.Equal(oidDomain):
			c.Domain, haveDomain = s, true
		case e.Id.Equal(oidCaps):
			if s != "" {
				c.Caps = strings.Split(s, ",")
			}
			haveCaps = true
		case e.Id.Equal(oidExpiry):
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return Claims{}, fmt.Errorf("machinecert: malformed expiry: %w", err)
			}
			if t.Before(c.NotAfter) {
				c.NotAfter = t
			}
		}
	}
	if !haveDomain || !haveCaps || c.Name == "" {
		return Claims{}, ErrNoClaims
	}
	return c, nil
}

// PEM encodes a DER certificate.
func PEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// PrivatePEM encodes an Ed25519 private key as PKCS #8.
func PrivatePEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseBundle reads the file `machine issue` writes: a private key, the client
// certificate and the CA certificate, each PEM encoded.
func ParseBundle(data []byte) (key ed25519.PrivateKey, client *x509.Certificate, clientDER []byte, ca *x509.Certificate, err error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch b.Type {
		case "PRIVATE KEY":
			k, perr := x509.ParsePKCS8PrivateKey(b.Bytes)
			ek, ok := k.(ed25519.PrivateKey)
			if perr != nil || !ok {
				return nil, nil, nil, nil, errors.New("machinecert: the private key is not an Ed25519 key")
			}
			key = ek
		case "CERTIFICATE":
			cert, perr := x509.ParseCertificate(b.Bytes)
			if perr != nil {
				return nil, nil, nil, nil, perr
			}
			if cert.IsCA {
				ca = cert
			} else {
				client, clientDER = cert, b.Bytes
			}
		}
	}
	if key == nil || client == nil || ca == nil {
		return nil, nil, nil, nil, errors.New("machinecert: the file needs a private key, a client certificate and the CA certificate")
	}
	return key, client, clientDER, ca, nil
}
