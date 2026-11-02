// Package keyops performs signing, verification, encryption and decryption
// with keys that stay inside the daemon. A caller names a connection field and
// an algorithm; the key is read from the backend for the length of one
// operation and never returned, logged or written to the audit trail.
package keyops

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Operation names a key operation.
type Operation string

const (
	OpSign    Operation = "sign"
	OpVerify  Operation = "verify"
	OpEncrypt Operation = "encrypt"
	OpDecrypt Operation = "decrypt"
	OpJWTSign Operation = "jwt_sign"
	OpSSHSign Operation = "ssh_sign"
	OpGPGSign Operation = "gpg_sign"
)

var userOperations = []Operation{OpSign, OpVerify, OpEncrypt, OpDecrypt, OpJWTSign, OpGPGSign}

// Algorithm names use the JOSE registry.
const (
	HS256   = "HS256"
	HS384   = "HS384"
	HS512   = "HS512"
	EdDSA   = "EdDSA"
	ES256   = "ES256"
	ES384   = "ES384"
	PS256   = "PS256"
	RS256   = "RS256"
	A256GCM = "A256GCM"
)

var algorithmAliases = map[string]string{
	"HMAC-SHA256":         HS256,
	"HMAC-SHA384":         HS384,
	"HMAC-SHA512":         HS512,
	"ED25519":             EdDSA,
	"ECDSA-P256":          ES256,
	"ECDSA-P384":          ES384,
	"RSA-PSS":             PS256,
	"RSA-PSS-SHA256":      PS256,
	"RSA-PKCS1V15":        RS256,
	"RSA-PKCS1V15-SHA256": RS256,
	"AES-256-GCM":         A256GCM,
}

var (
	signingAlgorithms    = []string{HS256, HS384, HS512, EdDSA, ES256, ES384, PS256, RS256}
	encryptionAlgorithms = []string{A256GCM}
	jwtAlgorithms        = []string{HS256, ES256, EdDSA}
)

const (
	minRSABits    = 2048
	aesKeySize    = 32
	gcmNonceBytes = 12
)

// NormalizeAlgorithm returns the canonical algorithm name for name.
func NormalizeAlgorithm(name string) (string, bool) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", false
	}
	if canon, ok := algorithmAliases[strings.ToUpper(n)]; ok {
		return canon, true
	}
	for _, a := range slices.Concat(signingAlgorithms, encryptionAlgorithms) {
		if strings.EqualFold(a, n) {
			return a, true
		}
	}
	return "", false
}

func algorithmFits(op Operation, alg string) bool {
	switch op {
	case OpSign, OpVerify:
		return slices.Contains(signingAlgorithms, alg)
	case OpEncrypt, OpDecrypt:
		return slices.Contains(encryptionAlgorithms, alg)
	case OpJWTSign:
		return slices.Contains(jwtAlgorithms, alg)
	case OpGPGSign:
		return slices.Contains([]string{RS256, ES256, ES384, EdDSA}, alg)
	}
	return false
}

func isHMAC(alg string) bool { return alg == HS256 || alg == HS384 || alg == HS512 }

func newHash(alg string) func() hash.Hash {
	switch alg {
	case HS256, ES256, PS256, RS256:
		return sha256.New
	case HS384, ES384:
		return sha512.New384
	case HS512:
		return sha512.New
	}
	return nil
}

func digestOf(alg string, msg []byte) ([]byte, crypto.Hash) {
	h := newHash(alg)()
	h.Write(msg)
	switch alg {
	case ES384:
		return h.Sum(nil), crypto.SHA384
	}
	return h.Sum(nil), crypto.SHA256
}

// parsePrivateKey reads a PEM private key (PKCS#8, PKCS#1, SEC1 or OpenSSH).
func parsePrivateKey(b []byte) (crypto.Signer, error) {
	if !bytes.Contains(b, []byte("-----BEGIN")) {
		return nil, errors.New("key is not a PEM private key")
	}
	k, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	switch v := k.(type) {
	case *rsa.PrivateKey:
		if v.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("RSA key is smaller than %d bits", minRSABits)
		}
		return v, nil
	case *ecdsa.PrivateKey:
		return v, nil
	case ed25519.PrivateKey:
		return v, nil
	case *ed25519.PrivateKey:
		return *v, nil
	}
	return nil, errors.New("unsupported private key type")
}

func zeroSigner(s crypto.Signer) {
	if k, ok := s.(ed25519.PrivateKey); ok {
		clear(k)
	}
}

func signerFor(alg string, key []byte) (crypto.Signer, error) {
	s, err := parsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	ok := false
	switch alg {
	case EdDSA:
		_, ok = s.(ed25519.PrivateKey)
	case ES256:
		k, isEC := s.(*ecdsa.PrivateKey)
		ok = isEC && k.Curve == elliptic.P256()
	case ES384:
		k, isEC := s.(*ecdsa.PrivateKey)
		ok = isEC && k.Curve == elliptic.P384()
	case PS256, RS256:
		_, ok = s.(*rsa.PrivateKey)
	}
	if !ok {
		zeroSigner(s)
		return nil, fmt.Errorf("key does not match algorithm %s", alg)
	}
	return s, nil
}

// Sign signs msg. With jws set, ECDSA signatures are the fixed-width r||s
// encoding JOSE uses; otherwise they are ASN.1 DER.
func Sign(alg string, key, msg []byte, jws bool) ([]byte, error) {
	if isHMAC(alg) {
		if len(key) == 0 {
			return nil, errors.New("key is empty")
		}
		m := hmac.New(newHash(alg), key)
		m.Write(msg)
		return m.Sum(nil), nil
	}
	s, err := signerFor(alg, key)
	if err != nil {
		return nil, err
	}
	defer zeroSigner(s)
	switch alg {
	case EdDSA:
		return ed25519.Sign(s.(ed25519.PrivateKey), msg), nil
	case ES256, ES384:
		k := s.(*ecdsa.PrivateKey)
		d, _ := digestOf(alg, msg)
		der, err := ecdsa.SignASN1(rand.Reader, k, d)
		if err != nil {
			return nil, err
		}
		if !jws {
			return der, nil
		}
		return derToRaw(der, (k.Curve.Params().BitSize+7)/8)
	case PS256:
		d, h := digestOf(alg, msg)
		return rsa.SignPSS(rand.Reader, s.(*rsa.PrivateKey), h, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case RS256:
		d, h := digestOf(alg, msg)
		return rsa.SignPKCS1v15(rand.Reader, s.(*rsa.PrivateKey), h, d)
	}
	return nil, fmt.Errorf("unsupported algorithm %s", alg)
}

// Verify checks sig over msg with the public half of key.
func Verify(alg string, key, msg, sig []byte, jws bool) (bool, error) {
	if isHMAC(alg) {
		if len(key) == 0 {
			return false, errors.New("key is empty")
		}
		m := hmac.New(newHash(alg), key)
		m.Write(msg)
		return hmac.Equal(m.Sum(nil), sig), nil
	}
	s, err := signerFor(alg, key)
	if err != nil {
		return false, err
	}
	defer zeroSigner(s)
	switch alg {
	case EdDSA:
		return ed25519.Verify(s.Public().(ed25519.PublicKey), msg, sig), nil
	case ES256, ES384:
		k := s.(*ecdsa.PrivateKey)
		d, _ := digestOf(alg, msg)
		if jws {
			der, err := rawToDER(sig, (k.Curve.Params().BitSize+7)/8)
			if err != nil {
				return false, nil
			}
			sig = der
		}
		return ecdsa.VerifyASN1(&k.PublicKey, d, sig), nil
	case PS256:
		d, h := digestOf(alg, msg)
		return rsa.VerifyPSS(&s.(*rsa.PrivateKey).PublicKey, h, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil, nil
	case RS256:
		d, h := digestOf(alg, msg)
		return rsa.VerifyPKCS1v15(&s.(*rsa.PrivateKey).PublicKey, h, d, sig) == nil, nil
	}
	return false, fmt.Errorf("unsupported algorithm %s", alg)
}

type ecdsaSignature struct{ R, S *big.Int }

func derToRaw(der []byte, size int) ([]byte, error) {
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

func rawToDER(raw []byte, size int) ([]byte, error) {
	if len(raw) != 2*size {
		return nil, errors.New("signature has the wrong length")
	}
	return asn1.Marshal(ecdsaSignature{new(big.Int).SetBytes(raw[:size]), new(big.Int).SetBytes(raw[size:])})
}

// aesKey accepts 32 raw bytes, or 32 bytes written as hex or base64.
func aesKey(key []byte) ([]byte, error) {
	if len(key) == aesKeySize {
		return slices.Clone(key), nil
	}
	text := strings.TrimSpace(string(key))
	if b, err := hex.DecodeString(text); err == nil && len(b) == aesKeySize {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(text); err == nil && len(b) == aesKeySize {
			return b, nil
		}
	}
	return nil, errors.New("key is not 32 bytes")
}

func newGCM(key []byte) (cipher.AEAD, error) {
	k, err := aesKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt returns nonce || ciphertext || tag.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, gcmNonceBytes, gcmNonceBytes+len(plaintext)+g.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return g.Seal(out, out[:gcmNonceBytes], plaintext, aad), nil
}

// Decrypt reverses Encrypt.
func Decrypt(key, data, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(data) < gcmNonceBytes+g.Overhead() {
		return nil, errors.New("ciphertext is too short")
	}
	pt, err := g.Open(nil, data[:gcmNonceBytes], data[gcmNonceBytes:], aad)
	if err != nil {
		return nil, errors.New("ciphertext failed authentication")
	}
	return pt, nil
}
