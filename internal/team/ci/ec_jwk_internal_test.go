package ci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func ecJWK(t *testing.T, crv string, curve elliptic.Curve) (*ecdsa.PrivateKey, rawJWK) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes: %v", err)
	}
	size := (len(point) - 1) / 2
	enc := base64.RawURLEncoding.EncodeToString
	return priv, rawJWK{Kty: "EC", Kid: "k1", Crv: crv, X: enc(point[1 : 1+size]), Y: enc(point[1+size:])}
}

func TestParseECJWK_Curves(t *testing.T) {
	for _, tc := range []struct {
		crv   string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	} {
		t.Run(tc.crv, func(t *testing.T) {
			priv, jwk := ecJWK(t, tc.crv, tc.curve)
			pk, err := parseECJWK(jwk)
			if err != nil {
				t.Fatalf("parseECJWK: %v", err)
			}
			pub, ok := pk.Key.(*ecdsa.PublicKey)
			if !ok || !pub.Equal(&priv.PublicKey) {
				t.Fatalf("parsed key does not match generated key")
			}
		})
	}
}

func TestParseECJWK_VerifiesES256Signature(t *testing.T) {
	priv, jwk := ecJWK(t, "P-256", elliptic.P256())
	pk, err := parseECJWK(jwk)
	if err != nil {
		t.Fatalf("parseECJWK: %v", err)
	}
	input := "header.payload"
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if err := verifyEC(input, sig, "ES256", pk.Key.(*ecdsa.PublicKey)); err != nil {
		t.Fatalf("verifyEC: %v", err)
	}
}

func TestParseECJWK_AcceptsStrippedLeadingZeros(t *testing.T) {
	for i := 0; i < 1<<14; i++ {
		priv, jwk := ecJWK(t, "P-256", elliptic.P256())
		x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
		if x[0] != 0 {
			continue
		}
		jwk.X = base64.RawURLEncoding.EncodeToString(x[1:])
		pk, err := parseECJWK(jwk)
		if err != nil {
			t.Fatalf("parseECJWK with stripped x: %v", err)
		}
		if !pk.Key.(*ecdsa.PublicKey).Equal(&priv.PublicKey) {
			t.Fatalf("stripped encoding parsed to a different key")
		}
		return
	}
	t.Fatal("no key with a leading zero x byte generated")
}

func TestParseECJWK_Rejects(t *testing.T) {
	_, valid := ecJWK(t, "P-256", elliptic.P256())
	enc := base64.RawURLEncoding.EncodeToString
	cases := map[string]rawJWK{
		"missing x":       {Kty: "EC", Crv: "P-256", Y: valid.Y},
		"unknown curve":   {Kty: "EC", Crv: "P-192", X: valid.X, Y: valid.Y},
		"bad base64":      {Kty: "EC", Crv: "P-256", X: "!!", Y: valid.Y},
		"oversized x":     {Kty: "EC", Crv: "P-256", X: enc(make([]byte, 33)), Y: valid.Y},
		"point off curve": {Kty: "EC", Crv: "P-256", X: valid.X, Y: enc(make([]byte, 32))},
	}
	for name, jwk := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseECJWK(jwk); err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}
