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
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"math/bits"
	"os/exec"
	"strings"
	"testing"
	"time"
)

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
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, public := range map[string]crypto.PublicKey{"RSA": &rsaKey.PublicKey, "P256": &p256.PublicKey, "P384": &p384.PublicKey, "Ed25519": edPublic} {
		t.Run(name, func(t *testing.T) {
			grip, encoded, err := gpgPublic(public)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) == 0 {
				t.Fatal("missing public S-expression")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "--no-options", "--homedir", t.TempDir(), "--no-autostart", "--batch", "--with-colons", "--with-keygrip", "--import-options", "show-only", "--import")
			cmd.Stdin = bytes.NewReader(pgpPublicPacket(public))
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
