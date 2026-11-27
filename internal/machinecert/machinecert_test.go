package machinecert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCA(t *testing.T) (*x509.Certificate, []byte, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca, der, err := CA(key)
	require.NoError(t, err)
	return ca, der, key
}

func TestCAIsAPureFunctionOfTheKey(t *testing.T) {
	_, d1, key := newCA(t)
	_, d2, err := CA(key)
	require.NoError(t, err)
	assert.Equal(t, d1, d2)
	_, d3, _ := newCA(t)
	assert.NotEqual(t, d1, d3)
}

func TestClientCertificateCarriesClaims(t *testing.T) {
	ca, _, key := newCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	want := Claims{Name: "ci-1", Domain: "ci", Caps: []string{"call", "mint"}, NotAfter: now.Add(2 * time.Hour).UTC().Truncate(time.Second)}
	der, serial, err := IssueClient(ca, key, pub, want, now)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, serial.Cmp(cert.SerialNumber), 0)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now})
	require.NoError(t, err)

	got, err := ClaimsOf(cert)
	require.NoError(t, err)
	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Domain, got.Domain)
	assert.Equal(t, want.Caps, got.Caps)
	assert.True(t, want.NotAfter.Equal(got.NotAfter), "%v vs %v", want.NotAfter, got.NotAfter)

	// Another CA's certificate does not verify.
	other, _, otherKey := newCA(t)
	oder, _, _ := IssueClient(other, otherKey, pub, want, now)
	ocert, _ := x509.ParseCertificate(oder)
	_, err = ocert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	assert.Error(t, err)
}

func TestClaimsRejectCertificatesWithoutThem(t *testing.T) {
	ca, _, key := newCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, err := IssueServer(ca, key, pub, []string{"10.0.0.5", "broker.example", ""}, time.Now(), time.Now().Add(time.Hour))
	require.NoError(t, err)
	cert, _ := x509.ParseCertificate(der)
	_, err = ClaimsOf(cert)
	assert.ErrorIs(t, err, ErrNoClaims)
	assert.Len(t, cert.IPAddresses, 1)
	assert.Equal(t, []string{"broker.example"}, cert.DNSNames)

	// A claim with no capabilities is a certificate that may do nothing.
	cder, _, _ := IssueClient(ca, key, pub, Claims{Name: "n", Domain: "d", NotAfter: time.Now().Add(time.Hour)}, time.Now())
	ccert, _ := x509.ParseCertificate(cder)
	c, err := ClaimsOf(ccert)
	require.NoError(t, err)
	assert.Empty(t, c.Caps)
}

func TestBundleRoundTrip(t *testing.T) {
	ca, caDER, key := newCA(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _, _ := IssueClient(ca, key, pub, Claims{Name: "n", Domain: "d", Caps: []string{"call"}, NotAfter: time.Now().Add(time.Hour)}, time.Now())
	keyPEM, err := PrivatePEM(priv)
	require.NoError(t, err)
	bundle := append(append(append([]byte(nil), keyPEM...), PEM(der)...), PEM(caDER)...)

	gotKey, client, clientDER, gotCA, err := ParseBundle(bundle)
	require.NoError(t, err)
	assert.True(t, gotKey.Equal(priv))
	assert.Equal(t, der, clientDER)
	assert.Equal(t, "n", client.Subject.CommonName)
	assert.True(t, gotCA.Equal(ca))

	for name, data := range map[string][]byte{
		"empty":     nil,
		"no key":    append(PEM(der), PEM(caDER)...),
		"no ca":     append(append([]byte(nil), keyPEM...), PEM(der)...),
		"bad cert":  append(append([]byte(nil), keyPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})...),
		"rsa key":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
		"no client": append(append([]byte(nil), keyPEM...), PEM(caDER)...),
	} {
		_, _, _, _, err := ParseBundle(data)
		assert.Error(t, err, name)
	}
	assert.False(t, bytes.Contains(PEM(der), []byte("PRIVATE")))
}
