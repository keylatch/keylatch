package keyops

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
)

type gpgKey struct {
	ref    KeyRef
	signer crypto.Signer
	grip   string
	public []byte
}

func (s *Service) gpgKeys(ctx context.Context) ([]gpgKey, error) {
	refs, err := s.policy.GPGKeys()
	if err != nil {
		return nil, err
	}
	var keys []gpgKey
	for _, ref := range refs {
		raw, err := s.keys.Fetch(ctx, ref.Policy.Secret)
		if err != nil {
			continue
		}
		signer, err := parsePrivateKey(raw)
		clear(raw)
		if err != nil {
			continue
		}
		grip, public, err := gpgPublic(signer.Public())
		if err != nil {
			zeroSigner(signer)
			continue
		}
		keys = append(keys, gpgKey{ref: ref, signer: signer, grip: grip, public: public})
	}
	return keys, nil
}

// ServeGPGAgent serves a read-only Assuan signing session; it never imports or exports private keys.
func (s *Service) ServeGPGAgent(ctx context.Context, rw io.ReadWriter, caller Caller) error {
	scan := bufio.NewScanner(rw)
	scan.Buffer(make([]byte, 1024), 8192)
	out := bufio.NewWriter(rw)
	if _, err := out.WriteString("OK Keylatch signing agent\n"); err != nil {
		return err
	}
	if err := out.Flush(); err != nil {
		return err
	}
	var grip string
	var digest []byte
	var hash crypto.Hash
	defer func() { clear(digest) }()
	for scan.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		args := strings.Fields(scan.Text())
		if len(args) == 0 || strings.HasPrefix(args[0], "#") {
			continue
		}
		var result []byte
		var err error
		switch args[0] {
		case "BYE":
			_, _ = out.WriteString("OK closing connection\n")
			return out.Flush()
		case "RESET":
			grip = ""
			clear(digest)
			digest = nil
			hash = 0
		case "OPTION":
			err = gpgOption(args[1:])
		case "SETKEYDESC":
			// Untrusted client text must never become a presence prompt.
			if len(args) < 2 {
				err = ErrInvalid
			}
		case "GETINFO":
			if len(args) == 2 && args[1] == "version" {
				result = []byte("2.4.0-keylatch")
			} else {
				err = ErrInvalid
			}
		case "SIGKEY":
			grip = ""
			if len(args) != 2 {
				err = ErrInvalid
				break
			}
			candidate := strings.ToUpper(args[1])
			_, err = s.gpgLookup(ctx, candidate, func(gpgKey) ([]byte, error) { return nil, nil })
			if err == nil {
				grip = candidate
			}
		case "SETHASH":
			clear(digest)
			digest = nil
			hash, digest, err = gpgHash(args[1:])
		case "PKSIGN":
			if len(args) != 1 || grip == "" || len(digest) == 0 {
				err = ErrInvalid
				if auditErr := s.record(ctx, caller, OpGPGSign, KeyRef{}, "", digest, audit.OutcomeDenied, "invalid GnuPG signing state"); auditErr != nil {
					err = ErrUnavailable
				}
			} else {
				result, err = s.gpgSign(ctx, caller, grip, hash, digest)
			}
			grip = ""
			clear(digest)
			digest = nil
			hash = 0
		case "READKEY":
			if len(args) != 2 {
				err = ErrInvalid
				break
			}
			result, err = s.gpgLookup(ctx, strings.ToUpper(args[1]), func(key gpgKey) ([]byte, error) { return key.public, nil })
		case "HAVEKEY":
			if len(args) < 2 {
				err = ErrInvalid
				break
			}
			err = ErrNotFound
			for _, candidate := range args[1:] {
				if _, found := s.gpgLookup(ctx, strings.ToUpper(candidate), func(gpgKey) ([]byte, error) { return nil, nil }); found == nil {
					err = nil
					break
				}
			}
		default:
			err = ErrDenied
		}
		if err != nil {
			_, _ = out.WriteString("ERR 67108865 Operation refused\n")
		} else {
			if len(result) != 0 {
				writeGPGData(out, result)
			}
			_, _ = out.WriteString("OK\n")
		}
		if err := out.Flush(); err != nil {
			return err
		}
	}
	return scan.Err()
}

func gpgOption(args []string) error {
	if len(args) != 1 {
		return ErrInvalid
	}
	name, _, _ := strings.Cut(args[0], "=")
	switch name {
	case "putenv":
		// GnuPG forwards session metadata; clients cannot change the daemon environment.
		return nil
	case "ttyname", "ttytype", "display", "lc-ctype", "lc-messages", "allow-pinentry-notify", "agent-awareness", "pinentry-mode", "use-cache-for-signing":
		return nil
	default:
		return ErrDenied
	}
}

func gpgHash(args []string) (crypto.Hash, []byte, error) {
	if len(args) != 2 {
		return 0, nil, ErrInvalid
	}
	var hash crypto.Hash
	switch args[0] {
	case "8", "--hash=sha256":
		hash = crypto.SHA256
	case "9", "--hash=sha384":
		hash = crypto.SHA384
	case "10", "--hash=sha512":
		hash = crypto.SHA512
	default:
		return 0, nil, ErrDenied
	}
	digest, err := hex.DecodeString(args[1])
	if err != nil || len(digest) != hash.Size() {
		clear(digest)
		return 0, nil, ErrInvalid
	}
	return hash, digest, nil
}

func writeGPGData(out *bufio.Writer, data []byte) {
	for len(data) > 0 {
		n := min(len(data), 240)
		_, _ = out.WriteString("D ")
		for _, b := range data[:n] {
			if b == '%' || b == '\n' || b == '\r' {
				_, _ = fmt.Fprintf(out, "%%%02X", b)
			} else {
				_ = out.WriteByte(b)
			}
		}
		_ = out.WriteByte('\n')
		data = data[n:]
	}
}

func (s *Service) gpgLookup(ctx context.Context, grip string, use func(gpgKey) ([]byte, error)) ([]byte, error) {
	if len(grip) != 40 {
		return nil, ErrInvalid
	}
	if _, err := hex.DecodeString(grip); err != nil {
		return nil, ErrInvalid
	}
	keys, err := s.gpgKeys(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, key := range keys {
			zeroSigner(key.signer)
		}
	}()
	for _, key := range keys {
		if key.grip == grip {
			return use(key)
		}
	}
	return nil, ErrNotFound
}

func (s *Service) gpgSign(ctx context.Context, caller Caller, grip string, hash crypto.Hash, digest []byte) ([]byte, error) {
	var ref KeyRef
	var alg string
	signature, err := s.gpgLookup(ctx, grip, func(key gpgKey) ([]byte, error) {
		ref = key.ref
		switch key.signer.(type) {
		case *rsa.PrivateKey:
			if hash == crypto.SHA256 {
				alg = RS256
			}
		case *ecdsa.PrivateKey:
			if key.signer.Public().(*ecdsa.PublicKey).Curve.Params().BitSize == 256 && hash == crypto.SHA256 {
				alg = ES256
			}
			if key.signer.Public().(*ecdsa.PublicKey).Curve.Params().BitSize == 384 && hash == crypto.SHA384 {
				alg = ES384
			}
		case ed25519.PrivateKey:
			alg = EdDSA
		}
		var err error
		if alg == "" {
			err = ErrDenied
		} else {
			var current KeyRef
			current, _, err = s.authorize(caller, Request{Operation: OpGPGSign, Connection: key.ref.Connection, Field: key.ref.Field, Alg: alg, Input: digest})
			if err == nil && current.Policy.Secret != key.ref.Policy.Secret {
				err = ErrDenied
			}
		}
		var signature []byte
		if err == nil {
			signature, err = gpgSignature(key.signer, hash, digest)
		}
		return signature, err
	})
	outcome, reason := audit.OutcomeOK, ""
	if err != nil {
		outcome, reason = audit.OutcomeDenied, "GnuPG signing is not allowed"
	}
	if auditErr := s.record(ctx, caller, OpGPGSign, ref, alg, digest, outcome, reason); auditErr != nil {
		clear(signature)
		return nil, ErrUnavailable
	}
	return signature, err
}

func gpgSignature(signer crypto.Signer, hash crypto.Hash, digest []byte) ([]byte, error) {
	var body []byte
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
		if err != nil {
			return nil, err
		}
		body = gpgList(gpgAtom([]byte("rsa")), gpgParam("s", sig))
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		body = gpgList(gpgAtom([]byte("ecdsa")), gpgParam("r", gpgPositive(r)), gpgParam("s", gpgPositive(s)))
	case ed25519.PrivateKey:
		sig := ed25519.Sign(key, digest)
		body = gpgList(gpgAtom([]byte("eddsa")), gpgParam("r", sig[:32]), gpgParam("s", sig[32:]))
	default:
		return nil, errors.New("unsupported GnuPG signing key")
	}
	return gpgList(gpgAtom([]byte("sig-val")), body), nil
}
