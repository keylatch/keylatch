package brokerd

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/keylatch/keylatch/internal/control"
)

// Signed presence: a helper in the user's login session holds a private key
// that only releases signatures after the human proves presence (Touch ID or
// password with the Secure Enclave, Windows Hello). The daemon sends a fresh
// challenge that names the action, and accepts the answer only when it verifies
// against the public key registered for that user by root. A client that talks
// to the daemon directly has no key and so cannot produce a signature.

// Errors of signed presence.
var (
	ErrNoHelper      = errors.New("brokerd: the presence helper of this user is not connected")
	ErrBadSignature  = errors.New("brokerd: the presence signature does not verify")
	ErrNoPresenceKey = errors.New("brokerd: no presence key is registered for this user")
)

const (
	presenceDomain = "keylatch-presence-v1"
	nonceLen       = 32
	minRSABits     = 2048
	maxHelperLine  = 64 << 10
)

// Challenge is what the helper signs. Message is the exact byte string, so the
// helper and the daemon cannot disagree about what was approved.
type Challenge struct {
	Nonce   []byte
	Action  string
	Summary string
}

// Message returns the domain-separated bytes both sides sign and verify.
func (c Challenge) Message() []byte {
	var b []byte
	put := func(p []byte) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p))) //nolint:gosec // G115: bounded by the frame limit
		b = append(b, p...)
	}
	put([]byte(presenceDomain))
	put(c.Nonce)
	put([]byte(c.Action))
	put([]byte(c.Summary))
	return b
}

// KeyStore returns the registered presence public key of a user.
type KeyStore interface {
	PresenceKey(uid uint32) (crypto.PublicKey, error)
}

// HelperLink reaches the presence helper of a user and returns its signature
// over challenge.Message().
type HelperLink interface {
	Sign(ctx context.Context, uid uint32, c Challenge) ([]byte, error)
}

// SignedPresence is a PresenceMethod backed by a per-user helper.
type SignedPresence struct {
	// Platform names the method: "secure-enclave" or "windows-hello".
	Platform string
	Keys     KeyStore
	Link     HelperLink
	// Rand supplies nonces; crypto/rand when nil.
	Rand io.Reader
}

// Name implements PresenceMethod.
func (p *SignedPresence) Name() string { return p.Platform }

// Verify implements PresenceMethod.
func (p *SignedPresence) Verify(ctx context.Context, s Subject, action, summary string) error {
	pub, err := p.Keys.PresenceKey(s.UID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
	}
	rd := p.Rand
	if rd == nil {
		rd = rand.Reader
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rd, nonce); err != nil {
		return fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
	}
	c := Challenge{Nonce: nonce, Action: action, Summary: summary}
	sig, err := p.Link.Sign(ctx, s.UID, c)
	if err != nil {
		if errors.Is(err, ErrNoHelper) {
			return fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
		}
		return err
	}
	if len(sig) == 0 {
		return ErrBadSignature
	}
	return verifySignature(pub, c.Message(), sig)
}

func verifySignature(pub crypto.PublicKey, msg, sig []byte) error {
	sum := sha256.Sum256(msg)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, sum[:], sig) {
			return ErrBadSignature
		}
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig) != nil {
			return ErrBadSignature
		}
	default:
		return ErrBadSignature
	}
	return nil
}

// ParsePresenceKey reads a PEM public key (PKIX) and accepts only the key types
// the platform helpers produce: ECDSA P-256 and RSA of at least 2048 bits.
func ParsePresenceKey(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("brokerd: the presence key must be a PEM PUBLIC KEY")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("brokerd: presence key: %w", err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("brokerd: the presence key must be on P-256")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("brokerd: the presence key must have at least %d bits", minRSABits)
		}
	default:
		return nil, errors.New("brokerd: the presence key must be ECDSA or RSA")
	}
	return pub, nil
}

// DirKeys keeps one public key per user in a directory only root or an
// administrator can write.
type DirKeys struct {
	Dir string
	// NameOf names the file of a user number. Nil uses the number itself; the
	// Windows broker uses the account SID, which an administrator knows when
	// enrolling and the service maps back from the number.
	NameOf func(uid uint32) (string, bool)
}

var keyFileName = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

func (d DirKeys) nameOf(uid uint32) (string, bool) {
	if d.NameOf != nil {
		return d.NameOf(uid)
	}
	return uidString(uid), true
}

// PathOf is where the key named name is kept.
func (d DirKeys) PathOf(name string) string { return filepath.Join(d.Dir, name+".pem") }

// Path is where uid's key is kept.
func (d DirKeys) Path(uid uint32) string {
	name, _ := d.nameOf(uid)
	return d.PathOf(name)
}

// PresenceKey implements KeyStore.
func (d DirKeys) PresenceKey(uid uint32) (crypto.PublicKey, error) {
	name, ok := d.nameOf(uid)
	if !ok || !keyFileName.MatchString(name) {
		return nil, ErrNoPresenceKey
	}
	b, err := os.ReadFile(d.PathOf(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoPresenceKey
	}
	if err != nil {
		return nil, err
	}
	return ParsePresenceKey(b)
}

// Enroll registers pemBytes as uid's presence key. It is called by the
// installer under root, never by the daemon on a client's request: a key a
// client could register would let that client approve itself.
func (d DirKeys) Enroll(uid uint32, pemBytes []byte) error {
	name, ok := d.nameOf(uid)
	if !ok {
		return ErrNoPresenceKey
	}
	return d.EnrollNamed(name, pemBytes)
}

// EnrollNamed registers pemBytes under name.
func (d DirKeys) EnrollNamed(name string, pemBytes []byte) error {
	if !keyFileName.MatchString(name) {
		return fmt.Errorf("brokerd: %q is not a valid key name", name)
	}
	if _, err := ParsePresenceKey(pemBytes); err != nil {
		return err
	}
	if err := os.MkdirAll(d.Dir, 0o755); err != nil { //nolint:gosec // G301: public keys only; the daemon account reads them
		return err
	}
	tmp := d.PathOf(name) + ".new"
	if err := os.WriteFile(tmp, pemBytes, 0o644); err != nil { //nolint:gosec // G306: a public key
		return err
	}
	return os.Rename(tmp, d.PathOf(name))
}

// helperRequest and helperReply are the lines exchanged with a connected helper.
type helperRequest struct {
	ID      uint64 `json:"id"`
	Nonce   []byte `json:"nonce"`
	Action  string `json:"action"`
	Summary string `json:"summary"`
}

type helperReply struct {
	ID        uint64 `json:"id"`
	Signature []byte `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

type helper struct {
	conn control.Conn
	wmu  sync.Mutex
	resp chan helperReply
	done chan struct{}
}

// HelperHub holds the connections of the presence helpers. A helper dials the
// broker like any client and stays connected; the daemon sends it challenges.
type HelperHub struct {
	mu   sync.Mutex
	subs map[uint32]*helper
	next uint64
}

// NewHelperHub returns an empty hub.
func NewHelperHub() *HelperHub { return &HelperHub{subs: map[uint32]*helper{}} }

// Serve registers conn as the helper of uid and blocks until it closes. A new
// helper replaces the old one.
func (h *HelperHub) Serve(uid uint32, conn control.Conn) {
	hp := &helper{conn: conn, resp: make(chan helperReply, 1), done: make(chan struct{})}
	h.mu.Lock()
	old := h.subs[uid]
	h.subs[uid] = hp
	h.mu.Unlock()
	if old != nil {
		_ = old.conn.Close()
	}
	defer func() {
		close(hp.done)
		h.mu.Lock()
		if h.subs[uid] == hp {
			delete(h.subs, uid)
		}
		h.mu.Unlock()
		_ = conn.Close()
	}()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), maxHelperLine)
	for sc.Scan() {
		var rep helperReply
		if json.Unmarshal(sc.Bytes(), &rep) != nil {
			return
		}
		select {
		case hp.resp <- rep:
		default:
		}
	}
}

// Connected reports whether uid has a helper connected.
func (h *HelperHub) Connected(uid uint32) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.subs[uid] != nil
}

// Sign implements HelperLink.
func (h *HelperHub) Sign(ctx context.Context, uid uint32, c Challenge) ([]byte, error) {
	h.mu.Lock()
	hp := h.subs[uid]
	h.next++
	id := h.next
	h.mu.Unlock()
	if hp == nil {
		return nil, ErrNoHelper
	}
	for len(hp.resp) > 0 {
		<-hp.resp
	}
	line, err := json.Marshal(helperRequest{ID: id, Nonce: c.Nonce, Action: c.Action, Summary: c.Summary})
	if err != nil {
		return nil, err
	}
	hp.wmu.Lock()
	if dl, ok := ctx.Deadline(); ok {
		_ = hp.conn.SetWriteDeadline(dl)
	}
	_, err = hp.conn.Write(append(line, '\n'))
	hp.wmu.Unlock()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.Join(ErrNoHelper, err)
	}
	for {
		select {
		case rep := <-hp.resp:
			if rep.ID != id {
				continue
			}
			if rep.Error != "" {
				return nil, fmt.Errorf("presence declined: %s", rep.Error)
			}
			return rep.Signature, nil
		case <-hp.done:
			return nil, ErrNoHelper
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
