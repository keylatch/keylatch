package keyops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // GnuPG keygrips are SHA-1 public-key identifiers, not signatures.
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

func gpgAtom(value []byte) []byte {
	return append(fmt.Appendf(nil, "%d:", len(value)), value...)
}

func gpgList(items ...[]byte) []byte {
	out := []byte{'('}
	for _, item := range items {
		out = append(out, item...)
	}
	return append(out, ')')
}

func gpgParam(name string, value []byte) []byte {
	return gpgList(gpgAtom([]byte(name)), gpgAtom(value))
}

func gpgPositive(value *big.Int) []byte {
	b := value.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// gpgPublic uses Libgcrypt's canonical public S-expression and keygrip encoding.
func gpgPublic(public crypto.PublicKey) (grip string, encoded []byte, err error) {
	h := sha1.New() //nolint:gosec // Protocol-mandated public identifier only.
	var algorithm []byte
	switch key := public.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < minRSABits {
			return "", nil, errors.New("GnuPG RSA key is too small")
		}
		n := gpgPositive(key.N)
		_, _ = h.Write(n)
		algorithm = gpgList(gpgAtom([]byte("rsa")), gpgParam("n", n), gpgParam("e", gpgPositive(big.NewInt(int64(key.E)))))
	case *ecdsa.PublicKey:
		var name string
		switch key.Curve {
		case elliptic.P256():
			name = "NIST P-256"
		case elliptic.P384():
			name = "NIST P-384"
		default:
			return "", nil, errors.New("GnuPG curve is not supported")
		}
		params := key.Params()
		q, err := key.Bytes()
		if err != nil {
			return "", nil, err
		}
		width := (params.BitSize + 7) / 8
		g := make([]byte, 1+2*width)
		g[0] = 4
		params.Gx.FillBytes(g[1 : 1+width])
		params.Gy.FillBytes(g[1+width:])
		components := [][]byte{params.P.Bytes(), new(big.Int).Sub(params.P, big.NewInt(3)).Bytes(), params.B.Bytes(), g, params.N.Bytes(), q}
		for i, value := range components {
			_, _ = h.Write(gpgParam(string("pabgnq"[i]), value))
		}
		algorithm = gpgList(gpgAtom([]byte("ecc")), gpgParam("curve", []byte(name)), gpgParam("q", q))
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return "", nil, errors.New("invalid Ed25519 public key")
		}
		components := []string{
			"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
			"01",
			"2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A",
			"04216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A6666666666666666666666666666666666666666666666666666666666666658",
			"1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
		}
		for i, value := range components {
			b, _ := hex.DecodeString(value)
			_, _ = h.Write(gpgParam(string("pabgn"[i]), b))
		}
		_, _ = h.Write(gpgParam("q", key))
		algorithm = gpgList(gpgAtom([]byte("ecc")), gpgParam("curve", []byte("Ed25519")), gpgList(gpgAtom([]byte("flags")), gpgAtom([]byte("eddsa"))), gpgParam("q", append([]byte{0x40}, key...)))
	default:
		return "", nil, errors.New("GnuPG key type is not supported")
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), gpgList(gpgAtom([]byte("public-key")), algorithm), nil
}
