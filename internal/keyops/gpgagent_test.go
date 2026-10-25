package keyops

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestGPGSessionMetadataDoesNotChangeEnvironment(t *testing.T) {
	t.Setenv("KEYLATCH_GPG_TEST", "original")
	svc, _ := service(t, staticPolicy{}, mapKeys{})
	out := runAssuan(t, svc, "OPTION putenv=KEYLATCH_GPG_TEST=changed\nSETKEYDESC untrusted+prompt\n")
	if strings.Contains(out, "ERR ") || os.Getenv("KEYLATCH_GPG_TEST") != "original" {
		t.Fatal("session metadata changed daemon environment or was rejected")
	}
}

func TestGPGSigningAuditFailsClosed(t *testing.T) {
	keys := newTestKeys(t)
	private, err := parsePrivateKey(keys.rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroSigner(private)
	grip, _, err := gpgPublic(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	svc, events := service(t, fullPolicy("key", []string{string(OpGPGSign)}, RS256), mapKeys{"key": keys.rsaKey})
	digest := sha256.Sum256([]byte("input"))
	for _, candidate := range []string{strings.Repeat("0", 40), "invalid"} {
		if _, err := svc.gpgSign(t.Context(), Caller{}, candidate, crypto.SHA256, digest[:]); err == nil {
			t.Fatal("unknown key signed")
		}
	}
	runAssuan(t, svc, "PKSIGN\n")
	if len(events.events) != 3 {
		t.Fatalf("denied signing attempts not audited: %d", len(events.events))
	}
	events.fail = true
	sig, err := svc.gpgSign(t.Context(), Caller{}, grip, crypto.SHA256, digest[:])
	if !errors.Is(err, ErrUnavailable) || len(sig) != 0 {
		t.Fatalf("signature escaped failed audit: %x, %v", sig, err)
	}
}

type assuanIO struct {
	io.Reader
	io.Writer
}

type replacedGPGPolicy struct {
	staticPolicy
}

func (p replacedGPGPolicy) Lookup(connection, field string) (KeyRef, error) {
	ref, err := p.staticPolicy.Lookup(connection, field)
	ref.Policy.Secret = "replacement"
	return ref, err
}

func TestGPGRefusesReplacedKeyPolicy(t *testing.T) {
	keys := newTestKeys(t)
	private, err := parsePrivateKey(keys.rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroSigner(private)
	grip, _, err := gpgPublic(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	svc, events := service(t, fullPolicy("key", []string{string(OpGPGSign)}, RS256), mapKeys{"key": keys.rsaKey})
	svc.policy = replacedGPGPolicy{svc.policy.(staticPolicy)}
	digest := sha256.Sum256([]byte("input"))
	sig, err := svc.gpgSign(t.Context(), Caller{}, grip, crypto.SHA256, digest[:])
	if !errors.Is(err, ErrDenied) || len(sig) != 0 || len(events.events) != 1 {
		t.Fatalf("stale key signed after replacement: %x, %v, audit count %d", sig, err, len(events.events))
	}
}

func runAssuan(t *testing.T, svc *Service, input string) string {
	t.Helper()
	var out bytes.Buffer
	if err := svc.ServeGPGAgent(t.Context(), assuanIO{strings.NewReader(input), &out}, Caller{Kind: "agent", Constrained: true}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func assuanData(t *testing.T, output string) []byte {
	t.Helper()
	var data []byte
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "D ") {
			continue
		}
		line = line[2:]
		for len(line) > 0 {
			if line[0] == '%' {
				if len(line) < 3 {
					t.Fatal("truncated escaped data")
				}
				value, err := hex.DecodeString(line[1:3])
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, value[0])
				line = line[3:]
			} else {
				data = append(data, line[0])
				line = line[1:]
			}
		}
	}
	return data
}

func signaturePart(t *testing.T, signature []byte, name string) []byte {
	t.Helper()
	prefix := []byte("(1:" + name)
	i := bytes.Index(signature, prefix)
	if i < 0 {
		t.Fatalf("missing signature part %s", name)
	}
	b := signature[i+len(prefix):]
	j := bytes.IndexByte(b, ':')
	if j < 0 {
		t.Fatal("missing atom length")
	}
	n, err := strconv.Atoi(string(b[:j]))
	if err != nil || n > len(b)-j-1 {
		t.Fatal("invalid signature atom")
	}
	return b[j+1 : j+1+n]
}

func TestGPGAgentSignsOnlyAllowedAlgorithms(t *testing.T) {
	keys := newTestKeys(t)
	for _, tc := range []struct {
		name, alg string
		raw       []byte
		hash      crypto.Hash
		hashID    string
	}{
		{"rsa", RS256, keys.rsaKey, crypto.SHA256, "8"},
		{"p256", ES256, keys.es256, crypto.SHA256, "8"},
		{"p384", ES384, keys.es384, crypto.SHA384, "9"},
		{"ed25519", EdDSA, keys.ed, crypto.SHA512, "10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			private, err := parsePrivateKey(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			defer zeroSigner(private)
			grip, _, err := gpgPublic(private.Public())
			if err != nil {
				t.Fatal(err)
			}
			h := tc.hash.New()
			_, _ = h.Write([]byte("OpenPGP signature material"))
			digest := h.Sum(nil)
			svc, audit := service(t, fullPolicy("key", []string{string(OpGPGSign)}, tc.alg), mapKeys{"key": tc.raw})
			input := fmt.Sprintf("SIGKEY %s\nSETHASH %s %x\nPKSIGN\n", grip, tc.hashID, digest)
			out := runAssuan(t, svc, input)
			if strings.Contains(out, "ERR ") {
				t.Fatalf("signing refused: %s", out)
			}
			sig := assuanData(t, out)
			switch public := private.Public().(type) {
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(public, tc.hash, digest, signaturePart(t, sig, "s")); err != nil {
					t.Fatal(err)
				}
			case *ecdsa.PublicKey:
				if !ecdsa.Verify(public, digest, new(big.Int).SetBytes(signaturePart(t, sig, "r")), new(big.Int).SetBytes(signaturePart(t, sig, "s"))) {
					t.Fatal("ECDSA signature invalid")
				}
			case ed25519.PublicKey:
				if !ed25519.Verify(public, digest, append(signaturePart(t, sig, "r"), signaturePart(t, sig, "s")...)) {
					t.Fatal("Ed25519 signature invalid")
				}
			}
			assertAbsent(t, out, tc.raw)
			assertAbsent(t, audit.dump(), tc.raw)
			if !strings.Contains(audit.dump(), `"operation":"gpg_sign"`) {
				t.Fatal("missing signing audit")
			}
			out = runAssuan(t, svc, input+"PKSIGN\n")
			if !strings.HasSuffix(out, "ERR 67108865 Operation refused\n") {
				t.Fatal("PKSIGN reused prior key/hash state")
			}
		})
	}
}

func TestGPGAgentRefusesUnsafeRequests(t *testing.T) {
	keys := newTestKeys(t)
	private, err := parsePrivateKey(keys.rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroSigner(private)
	grip, _, err := gpgPublic(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := service(t, fullPolicy("key", []string{string(OpGPGSign)}, RS256), mapKeys{"key": keys.rsaKey})
	digest := sha512.Sum512([]byte("not an RS256 digest"))
	for _, input := range []string{
		"EXPORT_KEY " + grip + "\n", "IMPORT_KEY\n", "GENKEY\n", "PKDECRYPT\n", "GET_PASSPHRASE\n",
		fmt.Sprintf("SIGKEY %s\nSETHASH 10 %x\nPKSIGN\n", grip, digest),
		fmt.Sprintf("SIGKEY %s\nSETHASH 8 00\nPKSIGN\n", grip),
		"SETHASH 2 " + strings.Repeat("00", 20) + "\n", "SIGKEY ../../private\n", "OPTION unknown=1\n",
	} {
		if out := runAssuan(t, svc, input); !strings.Contains(out, "ERR ") {
			t.Fatalf("accepted %q: %s", input, out)
		}
	}
	ordinary, _ := service(t, fullPolicy("key", []string{"sign"}, RS256), mapKeys{"key": keys.rsaKey})
	if out := runAssuan(t, ordinary, "HAVEKEY "+grip+"\n"); !strings.Contains(out, "ERR ") {
		t.Fatal("ordinary signing permission exposed GnuPG key")
	}
	wrongAlg, _ := service(t, fullPolicy("key", []string{string(OpGPGSign)}, EdDSA), mapKeys{"key": keys.rsaKey})
	sha := sha256.Sum256([]byte("input"))
	if out := runAssuan(t, wrongAlg, fmt.Sprintf("SIGKEY %s\nSETHASH 8 %x\nPKSIGN\n", grip, sha)); !strings.Contains(out, "ERR ") {
		t.Fatal("algorithm allowlist bypassed")
	}
}
