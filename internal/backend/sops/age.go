package sops

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// This file decrypts files in the age v1 format for X25519 recipients, which is
// what sops stores its data key in. Passphrase, SSH and plugin recipients are
// not supported: the daemon holds an age identity, not a person's passphrase.

const (
	ageVersionLine = "age-encryption.org/v1"
	ageSecretHRP   = "age-secret-key-"
	ageChunk       = 64 << 10
	ageFileKeyLen  = 16
)

var b64 = base64.RawStdEncoding

// ErrNoIdentity means none of the supplied age identities opens the file.
var ErrNoIdentity = errors.New("sops: none of the age identities can open the data key")

// Identity is an age X25519 secret key.
type Identity struct {
	secret [32]byte
	public [32]byte
}

// Clear wipes the secret key.
func (i *Identity) Clear() { clear(i.secret[:]) }

// ParseIdentities reads an age identity file: comment lines start with '#',
// each other non-empty line is an AGE-SECRET-KEY-1... string.
func ParseIdentities(r io.Reader) ([]*Identity, error) {
	var ids []*Identity
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hrp, data, err := bech32Decode(line)
		if err != nil || hrp != ageSecretHRP {
			return nil, errors.New("sops: the age identity is not an AGE-SECRET-KEY-1 string")
		}
		raw, err := convertBits(data, 5, 8)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("sops: the age identity has the wrong length")
		}
		id := &Identity{}
		copy(id.secret[:], raw)
		clear(raw)
		pub, err := curve25519.X25519(id.secret[:], curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		copy(id.public[:], pub)
		ids = append(ids, id)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New("sops: no age identity found")
	}
	return ids, nil
}

type stanza struct {
	args []string
	body []byte
}

// parseAgeHeader splits an age file into its stanzas, the header bytes the MAC
// covers, the MAC, and the payload.
func parseAgeHeader(file []byte) (stanzas []stanza, macInput, mac, payload []byte, err error) {
	rest := file
	line := func() (string, bool) {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			return "", false
		}
		l := string(rest[:i])
		rest = rest[i+1:]
		return l, true
	}
	if first, ok := line(); !ok || first != ageVersionLine {
		return nil, nil, nil, nil, errors.New("sops: not an age v1 file")
	}
	var cur *stanza
	for {
		before := len(file) - len(rest)
		l, ok := line()
		if !ok {
			return nil, nil, nil, nil, errors.New("sops: truncated age header")
		}
		switch {
		case strings.HasPrefix(l, "--- "):
			m, err := b64.DecodeString(strings.TrimPrefix(l, "--- "))
			if err != nil {
				return nil, nil, nil, nil, errors.New("sops: malformed age header MAC")
			}
			return stanzas, file[:before+3], m, rest, nil
		case strings.HasPrefix(l, "-> "):
			stanzas = append(stanzas, stanza{args: strings.Split(strings.TrimPrefix(l, "-> "), " ")})
			cur = &stanzas[len(stanzas)-1]
		default:
			if cur == nil {
				return nil, nil, nil, nil, errors.New("sops: malformed age header")
			}
			body, err := b64.DecodeString(l)
			if err != nil {
				return nil, nil, nil, nil, errors.New("sops: malformed age stanza body")
			}
			cur.body = append(cur.body, body...)
		}
	}
}

func hkdfKey(secret, salt []byte, info string) ([]byte, error) {
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, []byte(info)), out); err != nil {
		return nil, err
	}
	return out, nil
}

// unwrapX25519 recovers the file key from an X25519 stanza, or reports false
// when the stanza was written for another recipient.
func (i *Identity) unwrap(s stanza) ([]byte, bool) {
	if len(s.args) != 2 || s.args[0] != "X25519" {
		return nil, false
	}
	share, err := b64.DecodeString(s.args[1])
	if err != nil || len(share) != 32 {
		return nil, false
	}
	shared, err := curve25519.X25519(i.secret[:], share)
	if err != nil {
		return nil, false
	}
	salt := append(append([]byte{}, share...), i.public[:]...)
	key, err := hkdfKey(shared, salt, "age-encryption.org/v1/X25519")
	if err != nil {
		return nil, false
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, false
	}
	fileKey, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), s.body, nil)
	if err != nil || len(fileKey) != ageFileKeyLen {
		return nil, false
	}
	return fileKey, true
}

// decryptAge opens an age file (binary, or ASCII-armored) with the identities.
func decryptAge(file []byte, ids []*Identity) ([]byte, error) {
	if bytes.HasPrefix(bytes.TrimSpace(file), []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		var body strings.Builder
		for _, l := range strings.Split(string(file), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "-----") {
				continue
			}
			body.WriteString(l)
		}
		raw, err := base64.StdEncoding.DecodeString(body.String())
		if err != nil {
			return nil, errors.New("sops: malformed age armor")
		}
		file = raw
	}
	stanzas, macInput, mac, payload, err := parseAgeHeader(file)
	if err != nil {
		return nil, err
	}
	var fileKey []byte
	for _, s := range stanzas {
		for _, id := range ids {
			if k, ok := id.unwrap(s); ok {
				fileKey = k
			}
		}
	}
	if fileKey == nil {
		return nil, ErrNoIdentity
	}
	defer clear(fileKey)
	macKey, err := hkdfKey(fileKey, nil, "header")
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, macKey)
	h.Write(macInput)
	if !hmac.Equal(h.Sum(nil), mac) {
		return nil, errors.New("sops: the age header MAC does not verify")
	}
	if len(payload) < 16 {
		return nil, errors.New("sops: truncated age payload")
	}
	streamKey, err := hkdfKey(fileKey, payload[:16], "payload")
	if err != nil {
		return nil, err
	}
	defer clear(streamKey)
	return openStream(streamKey, payload[16:])
}

// openStream decrypts the STREAM construction: 64 KiB chunks, a counter in the
// nonce, and a final-chunk flag so truncation is detected.
func openStream(key, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var out []byte
	var counter uint64
	for first := true; first || len(ct) > 0; first = false {
		n := min(len(ct), ageChunk+chacha20poly1305.Overhead)
		last := n == len(ct)
		var nonce [chacha20poly1305.NonceSize]byte
		for i := 0; i < 8; i++ {
			nonce[3+i] = byte(counter >> (56 - 8*uint(i)) & 0xff)
		}
		if last {
			nonce[11] = 1
		}
		pt, err := aead.Open(nil, nonce[:], ct[:n], nil)
		if err != nil {
			return nil, fmt.Errorf("sops: the age payload does not verify: %w", err)
		}
		out = append(out, pt...)
		ct = ct[n:]
		counter++
		if last {
			break
		}
	}
	return out, nil
}
