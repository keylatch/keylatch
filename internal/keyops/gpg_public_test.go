package keyops

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // OpenPGP v4 public-key fingerprints use SHA-1.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func pgpPacket(tag byte, body []byte) []byte {
	return append(binary.BigEndian.AppendUint32([]byte{0xc0 | tag, 255}, uint32(len(body))), body...)
}

func selfSignedPublic(t *testing.T, key crypto.Signer) ([]byte, string) {
	t.Helper()
	public := pgpPublicPacket(key.Public())
	body := public[6:]
	keyHashInput := append(binary.BigEndian.AppendUint16([]byte{0x99}, uint16(len(body))), body...)
	fingerprint := sha1.Sum(keyHashInput) //nolint:gosec // OpenPGP v4 public identifier only.
	uid := []byte("Keylatch test <keylatch@example.invalid>")
	header := []byte{4, 0x13, body[5], 8, 0, 6, 5, 2, 0x65, 0x53, 0xf1, 0}
	if public, ok := key.Public().(*ecdsa.PublicKey); ok && public.Curve == elliptic.P384() {
		header[3] = 9
	}
	toHash := append([]byte(nil), keyHashInput...)
	toHash = binary.BigEndian.AppendUint32(append(toHash, 0xb4), uint32(len(uid)))
	toHash = append(toHash, uid...)
	toHash = append(toHash, header...)
	toHash = binary.BigEndian.AppendUint32(append(toHash, 4, 0xff), uint32(len(header)))
	sum := sha256.Sum256(toHash)
	digest := sum[:]
	if header[3] == 9 {
		sum := sha512.Sum384(toHash)
		digest = sum[:]
	}
	var signature []byte
	switch key := key.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signature = pgpMPI(sig)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signature = append(pgpMPI(r.Bytes()), pgpMPI(s.Bytes())...)
	case ed25519.PrivateKey:
		sig := ed25519.Sign(key, digest[:])
		signature = append(pgpMPI(sig[:32]), pgpMPI(sig[32:])...)
	default:
		t.Fatalf("unsupported fixture key %T", key)
	}
	cert := append(append([]byte(nil), header...), 0, 10, 9, 16)
	cert = append(cert, fingerprint[12:]...)
	cert = append(append(cert, digest[:2]...), signature...)
	return append(append(public, pgpPacket(13, uid)...), pgpPacket(2, cert)...), fmt.Sprintf("%X", fingerprint)
}

func pgpMPI(value []byte) []byte {
	value = bytes.TrimLeft(value, "\x00")
	n := 0
	if len(value) != 0 {
		n = (len(value)-1)*8 + bits.Len8(value[0])
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(n)), value...)
}

func pgpPublicPacket(public crypto.PublicKey) []byte {
	body := []byte{4, 0x65, 0x53, 0xf1, 0}
	switch key := public.(type) {
	case *rsa.PublicKey:
		body = append(body, 1)
		body = append(body, pgpMPI(key.N.Bytes())...)
		body = append(body, pgpMPI(big.NewInt(int64(key.E)).Bytes())...)
	case *ecdsa.PublicKey:
		oid, _ := hex.DecodeString("2a8648ce3d030107")
		if key.Curve == elliptic.P384() {
			oid, _ = hex.DecodeString("2b81040022")
		}
		body = append(body, 19, byte(len(oid)))
		body = append(body, oid...)
		encoded, err := key.Bytes()
		if err != nil {
			return nil
		}
		body = append(body, pgpMPI(encoded)...)
	case ed25519.PublicKey:
		oid, _ := hex.DecodeString("2b06010401da470f01")
		body = append(body, 22, byte(len(oid)))
		body = append(body, oid...)
		body = append(body, pgpMPI(append([]byte{0x40}, key...))...)
	}
	packet := []byte{0xc6, 255}
	packet = binary.BigEndian.AppendUint32(packet, uint32(len(body)))
	return append(packet, body...)
}

func TestGPGKeygripsMatchGnuPG(t *testing.T) {
	bin, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("GnuPG is not installed")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, private := range map[string]crypto.Signer{"RSA": rsaKey, "P256": p256, "P384": p384, "Ed25519": edPrivate} {
		t.Run(name, func(t *testing.T) {
			grip, encoded, err := gpgPublic(private.Public())
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) == 0 {
				t.Fatal("missing public S-expression")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			home := t.TempDir()
			if err := os.Chmod(home, 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, bin, "--no-options", "--homedir", ".", "--no-autostart", "--batch", "--with-colons", "--with-keygrip", "--import-options", "show-only", "--import")
			// A relative home works with native and MSYS GnuPG on Windows.
			cmd.Dir = home
			packet, _ := selfSignedPublic(t, private)
			cmd.Stdin = bytes.NewReader(packet)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("public-key inspection: %v: %s", err, out)
			}
			if !strings.Contains(string(out), "grp:::::::::"+grip+":") {
				t.Fatalf("keygrip %s differs from GnuPG: %s", grip, out)
			}
		})
	}
}
