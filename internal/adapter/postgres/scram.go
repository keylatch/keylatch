package postgres

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	scramMechanism = "SCRAM-SHA-256"
	maxScramIter   = 1 << 20
)

var errScram = errors.New("postgres: SCRAM exchange failed")

// scramClient runs the client side of SCRAM-SHA-256 without channel binding.
type scramClient struct {
	password  string
	nonce     string
	firstBare string
	serverSig []byte
}

func newSCRAMClient(password string) (*scramClient, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	c := &scramClient{password: password, nonce: base64.StdEncoding.EncodeToString(raw)}
	c.firstBare = "n=,r=" + c.nonce
	return c, nil
}

// first is the client-first-message.
func (c *scramClient) first() []byte { return []byte("n,," + c.firstBare) }

// final answers the server-first-message with the client-final-message.
func (c *scramClient) final(serverFirst []byte) ([]byte, error) {
	attrs := parseAttrs(string(serverFirst))
	nonce, salt64, iterS := attrs["r"], attrs["s"], attrs["i"]
	if !strings.HasPrefix(nonce, c.nonce) || len(nonce) == len(c.nonce) {
		return nil, fmt.Errorf("%w: server nonce", errScram)
	}
	salt, err := base64.StdEncoding.DecodeString(salt64)
	iter, ierr := strconv.Atoi(iterS)
	if err != nil || ierr != nil || iter < 1 || iter > maxScramIter {
		return nil, fmt.Errorf("%w: server parameters", errScram)
	}
	salted, err := pbkdf2.Key(sha256.New, c.password, salt, iter, sha256.Size)
	if err != nil {
		return nil, err
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	withoutProof := "c=biws,r=" + nonce
	authMessage := c.firstBare + "," + string(serverFirst) + "," + withoutProof
	sig := mac(stored[:], authMessage)
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ sig[i]
	}
	c.serverSig = mac(mac(salted, "Server Key"), authMessage)
	return []byte(withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)), nil
}

// verify checks the server-final-message proves the server knows the password.
func (c *scramClient) verify(serverFinal []byte) error {
	attrs := parseAttrs(string(serverFinal))
	if e := attrs["e"]; e != "" {
		return fmt.Errorf("%w: %s", errScram, e)
	}
	got, err := base64.StdEncoding.DecodeString(attrs["v"])
	if err != nil || subtle.ConstantTimeCompare(got, c.serverSig) != 1 {
		return fmt.Errorf("%w: server signature", errScram)
	}
	return nil
}

func mac(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func parseAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		if len(part) >= 2 && part[1] == '=' {
			out[part[:1]] = part[2:]
		}
	}
	return out
}
