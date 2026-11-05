package sops

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"strings"
)

// A sops data key is 32 bytes; every value is AES-256-GCM under it with the
// path of the value as additional data, so a value cannot be moved elsewhere.
const dataKeyLen = 32

var encValue = regexp.MustCompile(`^ENC\[AES256_GCM,data:(.*),iv:(.*),tag:(.*),type:(.*)\]$`)

// ErrMAC means the file's MAC does not match its contents: it was modified
// after sops wrote it.
var ErrMAC = errors.New("sops: the file's MAC does not verify")

// ErrUnsupported means the file uses something this reader does not implement.
var ErrUnsupported = errors.New("sops: unsupported file")

// Values is a decrypted document. Its secrets live in byte slices that Clear
// wipes.
type Values struct {
	root *vnode
}

type vnode struct {
	kids  map[string]*vnode
	order []string
	list  []*vnode
	val   []byte
	leaf  bool
}

// DecryptOptions controls decryption.
type DecryptOptions struct {
	// SkipMAC disables the check that the file was not modified after sops
	// wrote it. Values stay authenticated one by one; added, removed or
	// reordered values are not detected.
	SkipMAC bool
}

// Decrypt opens a sops file with the age identities and returns its values.
func Decrypt(format Format, data []byte, ids []*Identity, opts DecryptOptions) (*Values, error) {
	root, md, err := parse(format, data)
	if err != nil {
		return nil, err
	}
	if len(md.age) == 0 {
		return nil, fmt.Errorf("%w: the file has no age recipient (only age is supported)", ErrUnsupported)
	}
	var key []byte
	for _, r := range md.age {
		if k, err := decryptAge([]byte(r.enc), ids); err == nil {
			key = k
			break
		}
	}
	if key == nil {
		return nil, ErrNoIdentity
	}
	defer clear(key)
	if len(key) != dataKeyLen {
		return nil, fmt.Errorf("%w: the data key is %d bytes", ErrFormat, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if md.macOnlyEncrypted && !opts.SkipMAC {
		return nil, fmt.Errorf("%w: the file was written with --mac-only-encrypted, whose MAC this reader cannot verify; re-encrypt without it or set verify_mac to false", ErrUnsupported)
	}
	d := &decryptor{block: block, sum: sha512.New()}
	out := &vnode{kids: map[string]*vnode{}}
	if err := d.walk(root, nil, out); err != nil {
		out.clear()
		return nil, err
	}
	if !opts.SkipMAC {
		want, _, err := d.open(md.mac, md.lastModified)
		if err != nil {
			out.clear()
			return nil, fmt.Errorf("%w: %v", ErrMAC, err)
		}
		got := strings.ToUpper(hex.EncodeToString(d.sum.Sum(nil)))
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			out.clear()
			return nil, ErrMAC
		}
		clear(want)
	}
	return &Values{root: out}, nil
}

type decryptor struct {
	block cipher.Block
	sum   hash.Hash
}

// open decrypts one ENC[...] string with aad and returns the plaintext and its
// sops type.
func (d *decryptor) open(text, aad string) ([]byte, string, error) {
	m := encValue.FindStringSubmatch(text)
	if m == nil {
		return nil, "", errors.New("not an encrypted value")
	}
	data, err1 := base64.StdEncoding.DecodeString(m[1])
	iv, err2 := base64.StdEncoding.DecodeString(m[2])
	tag, err3 := base64.StdEncoding.DecodeString(m[3])
	if err := errors.Join(err1, err2, err3); err != nil || len(iv) == 0 {
		return nil, "", errors.New("malformed encrypted value")
	}
	gcm, err := cipher.NewGCMWithNonceSize(d.block, len(iv))
	if err != nil {
		return nil, "", err
	}
	plain, err := gcm.Open(nil, iv, append(data, tag...), []byte(aad))
	if err != nil {
		return nil, "", errors.New("the value does not authenticate")
	}
	return plain, m[4], nil
}

func pathAAD(path []string) string {
	var b strings.Builder
	for _, p := range path {
		b.WriteString(p)
		b.WriteByte(':')
	}
	return b.String()
}

func (d *decryptor) walk(n *node, path []string, out *vnode) error {
	switch n.kind {
	case mapNode:
		if out.kids == nil {
			out.kids = map[string]*vnode{}
		}
		for i, kid := range n.kids {
			if kid.kind == commentNode {
				continue
			}
			child := &vnode{}
			if err := d.walk(kid, append(path[:len(path):len(path)], n.keys[i]), child); err != nil {
				return err
			}
			if _, dup := out.kids[n.keys[i]]; !dup {
				out.order = append(out.order, n.keys[i])
			}
			out.kids[n.keys[i]] = child
		}
	case listNode:
		for _, kid := range n.kids {
			// sops stores a comment inside a YAML sequence as an element of type
			// comment. Comments are not part of the MAC and not values.
			if kid.kind == commentNode || isCommentValue(kid.text) {
				continue
			}
			child := &vnode{}
			if err := d.walk(kid, path, child); err != nil {
				return err
			}
			out.list = append(out.list, child)
		}
	default:
		out.leaf = true
		if !encValue.MatchString(n.text) {
			_, _ = d.sum.Write([]byte(n.text))
			out.val = []byte(n.text)
			return nil
		}
		plain, typ, err := d.open(n.text, pathAAD(path))
		if err != nil {
			return fmt.Errorf("sops: %s: %v", strings.Join(path, "/"), err)
		}
		_, _ = d.sum.Write(plain)
		out.val = typed(plain, typ)
	}
	return nil
}

func isCommentValue(text string) bool {
	m := encValue.FindStringSubmatch(text)
	return m != nil && m[4] == "comment"
}

// typed converts a decrypted value to the text Keylatch hands out; sops writes
// booleans Python-style.
func typed(plain []byte, typ string) []byte {
	if typ == "bool" {
		return []byte(strings.ToLower(string(plain)))
	}
	return plain
}

func (n *vnode) clear() {
	clear(n.val)
	for _, k := range n.kids {
		k.clear()
	}
	for _, k := range n.list {
		k.clear()
	}
}

// Clear wipes every decrypted value.
func (v *Values) Clear() { v.root.clear() }

// Lookup returns a copy of the value at path ("a/b/c"; list elements are
// addressed by their index), which the caller wipes.
func (v *Values) Lookup(path string) ([]byte, bool) {
	cur := v.root
	for _, seg := range strings.Split(path, "/") {
		switch {
		case cur.kids != nil && cur.kids[seg] != nil:
			cur = cur.kids[seg]
		case cur.list != nil:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(cur.list) {
				return nil, false
			}
			cur = cur.list[i]
		default:
			return nil, false
		}
	}
	if !cur.leaf {
		return nil, false
	}
	return append([]byte(nil), cur.val...), true
}
