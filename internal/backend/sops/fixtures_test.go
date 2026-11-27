package sops

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// kv is one ordered entry of a test document; v is a string, int, float64,
// bool, []kv (a mapping) or []any (a list).
type kv struct {
	k string
	v any
}

// bech32Encode is the inverse of bech32Decode, for building test identities.
func bech32Encode(hrp string, data []byte) string {
	var five []byte
	var acc, bits uint
	for _, b := range data {
		acc = acc<<8 | uint(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			five = append(five, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		five = append(five, byte(acc<<(5-bits)&31))
	}
	values := append(append(bech32HRPExpand(hrp), five...), 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(values) ^ 1
	for i := 0; i < 6; i++ {
		five = append(five, byte(mod>>(5*(5-uint(i)))&31))
	}
	var sb strings.Builder
	sb.WriteString(hrp + "1")
	for _, v := range five {
		sb.WriteByte(bech32Charset[v])
	}
	return sb.String()
}

type testKey struct {
	identity string
	public   []byte
}

func newKey(t *testing.T) testKey {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(secret, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{identity: strings.ToUpper(bech32Encode(ageSecretHRP, secret)), public: pub}
}

func (k testKey) ids(t *testing.T) []*Identity {
	t.Helper()
	ids, err := ParseIdentities(strings.NewReader("# created by a test\n" + k.identity + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func wrap76(s string, width int) []string {
	var out []string
	for len(s) > width {
		out = append(out, s[:width])
		s = s[width:]
	}
	return append(out, s)
}

// ageEncrypt writes an age v1 file for one X25519 recipient.
func ageEncrypt(t *testing.T, recipient []byte, plain []byte, armor bool) []byte {
	t.Helper()
	fileKey := make([]byte, ageFileKeyLen)
	eph := make([]byte, 32)
	nonce := make([]byte, 16)
	for _, b := range [][]byte{fileKey, eph, nonce} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	share, err := curve25519.X25519(eph, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(eph, recipient)
	if err != nil {
		t.Fatal(err)
	}
	wrapKey, _ := hkdfKey(shared, append(append([]byte{}, share...), recipient...), "age-encryption.org/v1/X25519")
	aead, _ := chacha20poly1305.New(wrapKey)
	body := aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), fileKey, nil)

	var hdr bytes.Buffer
	hdr.WriteString(ageVersionLine + "\n-> X25519 " + b64.EncodeToString(share) + "\n")
	for _, l := range wrap76(b64.EncodeToString(body), 64) {
		hdr.WriteString(l + "\n")
	}
	hdr.WriteString("---")
	macKey, _ := hkdfKey(fileKey, nil, "header")
	h := hmac.New(sha256.New, macKey)
	h.Write(hdr.Bytes())
	hdr.WriteString(" " + b64.EncodeToString(h.Sum(nil)) + "\n")

	streamKey, _ := hkdfKey(fileKey, nonce, "payload")
	sa, _ := chacha20poly1305.New(streamKey)
	out := append(hdr.Bytes(), nonce...)
	var counter uint64
	rest := plain
	for first := true; first || len(rest) > 0; first = false {
		n := min(len(rest), ageChunk)
		last := n == len(rest)
		var nn [12]byte
		for i := 0; i < 8; i++ {
			nn[3+i] = byte(counter >> (56 - 8*uint(i)))
		}
		if last {
			nn[11] = 1
		}
		out = sa.Seal(out, nn[:], rest[:n], nil)
		rest = rest[n:]
		counter++
	}
	if !armor {
		return out
	}
	var sb strings.Builder
	sb.WriteString("-----BEGIN AGE ENCRYPTED FILE-----\n")
	for _, l := range wrap76(base64.StdEncoding.EncodeToString(out), 64) {
		sb.WriteString(l + "\n")
	}
	sb.WriteString("-----END AGE ENCRYPTED FILE-----\n")
	return []byte(sb.String())
}

type sopsFile struct {
	dataKey []byte
	block   cipher.Block
	hash    interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
	modified string
}

func (s *sopsFile) encrypt(plain, typ string, aad string) string {
	iv := make([]byte, 32)
	_, _ = rand.Read(iv)
	gcm, _ := cipher.NewGCMWithNonceSize(s.block, len(iv))
	sealed := gcm.Seal(nil, iv, []byte(plain), []byte(aad))
	data, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	return fmt.Sprintf("ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:%s]",
		base64.StdEncoding.EncodeToString(data), base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(tag), typ)
}

// leaf encrypts one scalar and folds it into the MAC.
func (s *sopsFile) leaf(v any, path []string) string {
	var plain, typ string
	switch x := v.(type) {
	case string:
		plain, typ = x, "str"
	case int:
		plain, typ = strconv.Itoa(x), "int"
	case float64:
		plain, typ = strconv.FormatFloat(x, 'f', -1, 64), "float"
	case bool:
		plain, typ = plainText(x), "bool"
	}
	s.hash.Write([]byte(plain))
	return s.encrypt(plain, typ, pathAAD(path))
}

func newSopsFile(t *testing.T) *sopsFile {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	return &sopsFile{dataKey: key, block: block, hash: sha512.New(), modified: "2026-10-16T08:00:00Z"}
}

// encNode encrypts a document tree into a node tree of ENC strings.
func (s *sopsFile) encNode(v any, path []string) any {
	switch x := v.(type) {
	case []kv:
		out := make([]kv, len(x))
		for i, e := range x {
			if strings.HasSuffix(e.k, "_unencrypted") {
				s.hash.Write([]byte(plainText(e.v)))
				out[i] = e
				continue
			}
			out[i] = kv{e.k, s.encNode(e.v, append(path[:len(path):len(path)], e.k))}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = s.encNode(e, path)
		}
		return out
	}
	return s.leaf(v, path)
}

func (s *sopsFile) mac() string {
	sum := strings.ToUpper(hex.EncodeToString(s.hash.Sum(nil)))
	return s.encrypt(sum, "str", s.modified)
}

// writeJSON serializes entries in order.
func writeJSON(v any) string {
	switch x := v.(type) {
	case []kv:
		parts := make([]string, len(x))
		for i, e := range x {
			k, _ := json.Marshal(e.k)
			parts[i] = string(k) + ":" + writeJSON(e.v)
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = writeJSON(e)
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func writeYAML(v any, indent string) string {
	var sb strings.Builder
	switch x := v.(type) {
	case []kv:
		for _, e := range x {
			switch e.v.(type) {
			case []kv, []any:
				sb.WriteString(indent + e.k + ":\n" + writeYAML(e.v, indent+"  "))
			default:
				sb.WriteString(indent + e.k + ": " + yamlScalar(e.v) + "\n")
			}
		}
	case []any:
		for _, e := range x {
			sb.WriteString(indent + "- " + yamlScalar(e) + "\n")
		}
	}
	return sb.String()
}

func yamlScalar(v any) string {
	if s, ok := v.(string); ok && strings.HasPrefix(s, "ENC[") {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

type docOptions struct {
	armor      bool
	macOnlyEnc bool
}

// buildDoc encrypts doc for key in the given format and returns the file.
func buildDoc(t *testing.T, f Format, key testKey, doc []kv, o docOptions) []byte {
	t.Helper()
	s := newSopsFile(t)
	enc := s.encNode(doc, nil).([]kv)
	dataKeyFile := ageEncrypt(t, key.public, s.dataKey, true)
	mac := s.mac()
	switch f {
	case FormatJSON:
		meta := []kv{
			{"age", []any{[]kv{{"recipient", "age1test"}, {"enc", string(dataKeyFile)}}}},
			{"lastmodified", s.modified}, {"mac", mac}, {"unencrypted_suffix", "_unencrypted"}, {"version", "3.13.3"},
		}
		return []byte(writeJSON(append(enc, kv{"sops", meta})))
	case FormatYAML:
		var sb strings.Builder
		sb.WriteString(writeYAML(enc, ""))
		sb.WriteString("sops:\n    age:\n        - recipient: age1test\n          enc: |\n")
		for _, l := range strings.Split(strings.TrimSpace(string(dataKeyFile)), "\n") {
			sb.WriteString("            " + l + "\n")
		}
		sb.WriteString("    lastmodified: \"" + s.modified + "\"\n    mac: " + mac + "\n")
		if o.macOnlyEnc {
			sb.WriteString("    mac_only_encrypted: true\n")
		}
		sb.WriteString("    unencrypted_suffix: _unencrypted\n    version: 3.13.3\n")
		return []byte(sb.String())
	}
	var sb strings.Builder
	for _, e := range enc {
		sb.WriteString(e.k + "=" + e.v.(string) + "\n")
	}
	sb.WriteString("sops_age__list_0__map_enc=" + strings.ReplaceAll(string(dataKeyFile), "\n", `\n`) + "\n")
	sb.WriteString("sops_age__list_0__map_recipient=age1test\nsops_lastmodified=" + s.modified + "\nsops_mac=" + mac + "\nsops_unencrypted_suffix=_unencrypted\nsops_version=3.13.3\n")
	return []byte(sb.String())
}

var sampleDoc = []kv{
	{"db", []kv{{"password", "hunter2"}, {"port", 5432}, {"ssl", true}, {"ratio", 1.5}}},
	{"hosts", []any{"a.example", "b.example"}},
	{"stripe_key", "sk_live_example"},
	{"note_unencrypted", "public"},
}
